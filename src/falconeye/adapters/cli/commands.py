"""CLI command implementations."""

import asyncio
from pathlib import Path
from typing import Optional, List
from datetime import datetime
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn, TimeElapsedColumn
from rich.panel import Panel
from rich.live import Live
from rich.table import Table

from ...infrastructure.di.container import DIContainer
from ...infrastructure.config.config_loader import ConfigLoader
from ...infrastructure.presentation.error_presenter import ErrorPresenter
from ...infrastructure.streaming import ResultStreamer
from ...infrastructure.parallel import AnalysisTask, create_tasks_from_files
from ...application.commands.index_codebase import IndexCodebaseCommand
from ...application.commands.review_file import ReviewFileCommand
from ...domain.models.security import SecurityFinding
from ..formatters.formatter_factory import FormatterFactory


def index_command(
    path: Path,
    language: Optional[str],
    chunk_size: Optional[int],
    chunk_overlap: Optional[int],
    exclude: Optional[list[str]],
    project_id: Optional[str],
    force_reindex: bool,
    config_path: Optional[str],
    verbose: bool,
    console: Console,
):
    """
    Execute index command.

    Args:
        path: Path to codebase
        language: Language name
        chunk_size: Chunk size
        chunk_overlap: Chunk overlap
        exclude: Exclusion patterns
        project_id: Explicit project ID
        force_reindex: Force re-index all files
        config_path: Config file path
        verbose: Enable verbose output
        console: Rich console
    """
    console.print(Panel.fit(
        "[bold]FalconEYE Indexer[/bold]",
        border_style="blue"
    ))

    # Create DI container
    container = DIContainer.create(config_path)

    # Use config values if not specified
    if chunk_size is None:
        chunk_size = container.config.chunking.default_size
    if chunk_overlap is None:
        chunk_overlap = container.config.chunking.default_overlap
    if exclude is None:
        exclude = container.config.file_discovery.default_exclusions

    # Create command
    command = IndexCodebaseCommand(
        codebase_path=path,
        language=language,
        chunk_size=chunk_size,
        chunk_overlap=chunk_overlap,
        excluded_patterns=exclude,
        project_id=project_id,
        force_reindex=force_reindex,
    )

    # Execute with progress
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Indexing codebase...", total=None)

        try:
            codebase = asyncio.run(container.index_handler.handle(command))

            progress.update(task, description="[green]Indexing complete!")

            # Display summary
            console.print("")
            console.print(f"[green]Indexed {codebase.total_files} files[/green]")
            
            # Show all detected languages
            all_langs = codebase.all_languages
            if len(all_langs) == 1:
                console.print(f"[green]Language: {all_langs[0]}[/green]")
            else:
                langs_str = ", ".join(all_langs)
                console.print(f"[green]Languages: {langs_str}[/green]")
            
            console.print(f"[green]Total lines: {codebase.total_lines}[/green]")

        except KeyboardInterrupt:
            progress.update(task, description="[yellow]Indexing cancelled")
            error_msg = ErrorPresenter.present(KeyboardInterrupt(), verbose=verbose)
            console.print(f"\n{error_msg}")
            raise SystemExit(1)

        except Exception as e:
            progress.update(task, description="[red]Indexing failed!")
            error_msg = ErrorPresenter.present(e, verbose=verbose)
            console.print(f"\n{error_msg}")
            raise SystemExit(1)


def review_command(
    path: Path,
    language: Optional[str],
    validate: bool,
    top_k: Optional[int],
    output_format: Optional[str],
    output_file: Optional[Path],
    severity: Optional[str],
    config_path: Optional[str],
    verbose: bool,
    console: Console,
):
    """
    Execute review command.

    Args:
        path: Path to review
        language: Language name
        validate: Enable validation
        top_k: Context count
        output_format: Output format
        output_file: Output file
        severity: Minimum severity
        config_path: Config file path
        verbose: Verbose output
        console: Rich console
    """
    console.print(Panel.fit(
        "[bold]FalconEYE Security Review[/bold]",
        border_style="blue"
    ))

    # Create DI container
    container = DIContainer.create(config_path)

    # Use config values if not specified
    if top_k is None:
        top_k = container.config.analysis.top_k_context
    if output_format is None:
        output_format = container.config.output.default_format

    # Detect language if not specified
    if language is None:
        language = container.language_detector.detect_language(path)

    # Check if path is directory or file
    if path.is_dir():
        # Directory - review all files with parallel processing
        review = _review_directory_parallel(
            path=path,
            language=language,
            validate=validate,
            top_k=top_k,
            output_format=output_format,
            output_file=output_file,
            container=container,
            verbose=verbose,
            console=console,
        )

    else:
        # Single file - get system prompt for the detected language
        system_prompt = container.get_system_prompt(language)
        
        command = ReviewFileCommand(
            file_path=path,
            language=language,
            system_prompt=system_prompt,
            validate_findings=validate,
            top_k_context=top_k,
        )

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("Analyzing code...", total=None)

            try:
                review = asyncio.run(container.review_file_handler.handle(command))
                progress.update(task, description="[green]Analysis complete!")

            except KeyboardInterrupt:
                progress.update(task, description="[yellow]Analysis cancelled")
                error_msg = ErrorPresenter.present(KeyboardInterrupt(), verbose=verbose)
                console.print(f"\n{error_msg}")
                raise SystemExit(1)

            except Exception as e:
                progress.update(task, description="[red]Analysis failed!")
                error_msg = ErrorPresenter.present(e, verbose=verbose)
                console.print(f"\n{error_msg}")
                raise SystemExit(1)

    # Format output
    formatter = FormatterFactory.create(
        output_format,
        use_color=container.config.output.color,
        verbose=verbose
    )

    output = formatter.format_review(review)

    # Display or save
    if output_file:
        output_file.write_text(output)
        console.print(f"\n[green]Results saved to {output_file}[/green]")
    elif output_format == "json" and container.config.output.save_to_file:
        # Auto-save JSON to default location
        from datetime import datetime
        output_dir = Path(container.config.output.output_directory)
        output_dir.mkdir(parents=True, exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        project_name = path.name if path.is_dir() else path.stem
        auto_file = output_dir / f"falconeye_{project_name}_{timestamp}.json"
        
        auto_file.write_text(output)
        console.print(f"\n[green]Results saved to {auto_file}[/green]")
        
        # Also generate HTML report
        html_formatter = FormatterFactory.create("html")
        html_output = html_formatter.format_review(review)
        html_file = output_dir / f"falconeye_{project_name}_{timestamp}.html"
        html_file.write_text(html_output)
        console.print(f"[green]HTML report saved to {html_file}[/green]")
    else:
        console.print("")
        console.print(output)


def _review_directory_parallel(
    path: Path,
    language: str,
    validate: bool,
    top_k: int,
    output_format: str,
    output_file: Optional[Path],
    container: DIContainer,
    verbose: bool,
    console: Console,
):
    """
    Review a directory using parallel processing and streaming results.
    
    Args:
        path: Directory path to review
        language: Primary language
        validate: Enable validation
        top_k: Context count
        output_format: Output format
        output_file: Output file path
        container: DI container
        verbose: Verbose output
        console: Rich console
        
    Returns:
        SecurityReview with all findings
    """
    from ...domain.models.security import SecurityReview
    
    # Detect all languages in the codebase
    try:
        all_languages = container.language_detector.detect_all_languages(path)
        console.print(f"[cyan]Detected languages: {', '.join(all_languages)}[/cyan]")
    except Exception:
        all_languages = [language]
    
    # Collect files from all detected languages
    files: List[Path] = []
    for lang in all_languages:
        extensions = container.language_detector.LANGUAGE_EXTENSIONS.get(lang, [])
        for ext in extensions:
            files.extend(list(path.rglob(f"*{ext}")))
    
    # Remove duplicates and filter exclusions
    files = list(set(files))
    exclusions = container.config.file_discovery.default_exclusions
    files = [f for f in files if not any(excl.replace("*", "") in str(f) for excl in exclusions)]
    
    if not files:
        console.print(f"[yellow]No source files found in {path}[/yellow]")
        return SecurityReview.create(codebase_path=str(path), language=language)
    
    # Check if parallel processing is enabled
    parallel_enabled = container.config.parallel.enabled
    streaming_enabled = container.config.streaming.enabled
    
    console.print(f"[cyan]Found {len(files)} files to analyze[/cyan]")
    console.print(f"[cyan]Parallel processing: {'enabled' if parallel_enabled else 'disabled'} "
                  f"(workers: {container.config.parallel.max_workers})[/cyan]")
    
    # Setup output file for streaming
    if streaming_enabled and container.config.streaming.incremental_save:
        output_dir = Path(container.config.output.output_directory)
        output_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        project_name = path.name
        streaming_file = output_dir / f"falconeye_{project_name}_{timestamp}_live.html"
    else:
        streaming_file = None
    
    # Create result streamer
    streamer = ResultStreamer(
        output_file=streaming_file,
        flush_interval=container.config.streaming.flush_interval,
        incremental_save=streaming_enabled and container.config.streaming.incremental_save,
    )
    
    # Start streaming
    streamer.on_scan_start(str(path), len(files), "html" if streaming_file else "json")
    
    if streaming_file:
        console.print(f"[green]Live results: {streaming_file}[/green]")
    
    # Create analysis tasks
    tasks = create_tasks_from_files(
        files=files,
        language_detector=container.language_detector,
        plugin_registry=container.plugin_registry,
        validate_findings=validate,
        top_k_context=top_k,
    )
    
    # Setup callbacks for progress display
    findings_count = {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}
    files_completed = {"count": 0}
    current_file = {"name": ""}
    
    def on_file_start(file_path: str):
        current_file["name"] = Path(file_path).name
        streamer.on_file_start(file_path)
    
    def on_file_complete(file_path: str, findings: List[SecurityFinding], error: Optional[str]):
        files_completed["count"] += 1
        for finding in findings:
            findings_count["total"] += 1
            severity = finding.severity.value
            findings_count[severity] = findings_count.get(severity, 0) + 1
        streamer.on_file_complete(file_path, findings, error)
    
    def on_finding(finding: SecurityFinding, file_path: str):
        streamer.on_finding(finding, file_path)
    
    # Set callbacks on worker pool
    container.worker_pool.set_callbacks(
        on_file_start=on_file_start,
        on_file_complete=on_file_complete,
        on_finding=on_finding,
    )
    
    # Progress display
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        console=console,
        refresh_per_second=2,
    ) as progress:
        main_task = progress.add_task(
            f"[cyan]Analyzing {len(files)} files...",
            total=len(files)
        )
        
        try:
            # Run analysis with asyncio.run()
            # We use a wrapper that periodically updates progress
            async def run_analysis_with_updates():
                # Start the actual analysis
                analysis_task = asyncio.create_task(
                    container.worker_pool.analyze_files(tasks)
                )
                
                # Update progress while analysis runs
                while not analysis_task.done():
                    progress.update(
                        main_task,
                        completed=files_completed["count"],
                        description=f"[cyan]Analyzing: {current_file['name'][:30]}... "
                                   f"({findings_count['total']} findings)"
                    )
                    try:
                        await asyncio.wait_for(asyncio.shield(analysis_task), timeout=0.5)
                    except asyncio.TimeoutError:
                        continue
                    except Exception:
                        break
                
                return await analysis_task
            
            results = asyncio.run(run_analysis_with_updates())
            
        except KeyboardInterrupt:
            progress.update(main_task, description="[yellow]Analysis cancelled")
            console.print("\n[yellow]Analysis cancelled by user[/yellow]")
            # Return partial results
            review = streamer.on_scan_complete()
            return review
        
        progress.update(
            main_task,
            completed=len(files),
            description=f"[green]Analysis complete! ({findings_count['total']} findings)"
        )
    
    # Complete streaming and get final review
    review = streamer.on_scan_complete()
    
    # Display summary
    console.print("")
    console.print(Panel.fit(
        f"[bold green]Analysis Complete[/bold green]\n\n"
        f"Files analyzed: {files_completed['count']}\n"
        f"Total findings: {findings_count['total']}\n"
        f"  [red]Critical: {findings_count.get('critical', 0)}[/red]\n"
        f"  [yellow]High: {findings_count.get('high', 0)}[/yellow]\n"
        f"  [blue]Medium: {findings_count.get('medium', 0)}[/blue]\n"
        f"  [green]Low: {findings_count.get('low', 0)}[/green]",
        border_style="green"
    ))
    
    if streaming_file and streaming_file.exists():
        console.print(f"\n[green]Live report available at: {streaming_file}[/green]")
    
    return review


def scan_command(
    path: Path,
    language: Optional[str],
    validate: bool,
    output_format: Optional[str],
    output_file: Optional[Path],
    project_id: Optional[str],
    force_reindex: bool,
    config_path: Optional[str],
    verbose: bool,
    console: Console,
):
    """
    Execute scan command (index + review).

    Args:
        path: Path to scan
        language: Language name
        validate: Enable validation
        output_format: Output format
        output_file: Output file
        project_id: Explicit project ID
        force_reindex: Force re-index all files
        config_path: Config file path
        verbose: Verbose output
        console: Rich console
    """
    console.print(Panel.fit(
        "[bold]FalconEYE Full Scan[/bold]",
        border_style="blue"
    ))

    # Run index first
    console.print("\n[bold]Step 1: Indexing...[/bold]")
    index_command(
        path=path,
        language=language,
        chunk_size=None,
        chunk_overlap=None,
        exclude=None,
        project_id=project_id,
        force_reindex=force_reindex,
        config_path=config_path,
        verbose=verbose,
        console=console,
    )

    # Then review
    console.print("\n[bold]Step 2: Security Review...[/bold]")
    review_command(
        path=path,
        language=language,
        validate=validate,
        top_k=None,
        output_format=output_format,
        output_file=output_file,
        severity=None,
        config_path=config_path,
        verbose=verbose,
        console=console,
    )


def info_command(config_path: Optional[str], console: Console):
    """
    Execute info command.

    Args:
        config_path: Config file path
        console: Rich console
    """
    console.print(Panel.fit(
        "[bold]FalconEYE System Information[/bold]",
        border_style="blue"
    ))

    try:
        # Create DI container
        container = DIContainer.create(config_path)

        # Version info
        console.print("\n[bold]Version:[/bold]")
        console.print("  FalconEYE: 2.0.0")
        console.print("  Analysis: AI-powered (ZERO pattern matching)")

        # LLM info
        console.print("\n[bold]LLM Configuration:[/bold]")
        console.print(f"  Provider: {container.config.llm.provider}")
        console.print(f"  Analysis Model: {container.config.llm.model.analysis}")
        console.print(f"  Embedding Model: {container.config.llm.model.embedding}")
        console.print(f"  Base URL: {container.config.llm.base_url}")

        # Check LLM health
        try:
            is_healthy = asyncio.run(container.llm_service.health_check())
            if is_healthy:
                console.print("  Status: [green]Connected[/green]")
            else:
                console.print("  Status: [red]Not available[/red]")
        except Exception:
            console.print("  Status: [red]Connection failed[/red]")

        # Language support
        console.print("\n[bold]Supported Languages:[/bold]")
        languages = container.plugin_registry.get_supported_languages()
        console.print(f"  {', '.join(languages)}")

        # Storage info
        console.print("\n[bold]Storage:[/bold]")
        console.print(f"  Vector Store: {container.config.vector_store.persist_directory}")
        console.print(f"  Metadata: {container.config.metadata.persist_directory}")

        # Configuration info
        console.print("\n[bold]Configuration:[/bold]")
        config_info = ConfigLoader.get_config_info()
        if config_info["existing_configs"]:
            console.print("  Active configs:")
            for cfg in config_info["existing_configs"]:
                console.print(f"    - {cfg}")
        else:
            console.print("  Using default configuration")

    except Exception as e:
        console.print(f"\n[red]Error:[/red] {str(e)}")
        raise


def config_command(
    init: bool,
    path: Optional[str],
    show: bool,
    console: Console,
):
    """
    Execute config command.

    Args:
        init: Create default config
        path: Config file path
        show: Show current config
        console: Rich console
    """
    console.print(Panel.fit(
        "[bold]FalconEYE Configuration[/bold]",
        border_style="blue"
    ))

    if init:
        # Create default configuration
        try:
            config_path = ConfigLoader.create_default_config(path)
            console.print(f"\n[green]Configuration file created: {config_path}[/green]")
        except Exception as e:
            console.print(f"\n[red]Error:[/red] {str(e)}")
            raise

    elif show:
        # Show current configuration
        try:
            config = ConfigLoader.load(path)
            yaml_str = config.to_yaml()
            console.print("\n[bold]Current Configuration:[/bold]")
            console.print(yaml_str)
        except Exception as e:
            console.print(f"\n[red]Error:[/red] {str(e)}")
            raise

    else:
        # Show config info
        config_info = ConfigLoader.get_config_info()

        console.print("\n[bold]Configuration Files:[/bold]")
        if config_info["existing_configs"]:
            for cfg in config_info["existing_configs"]:
                console.print(f"  [green]{cfg}[/green]")
        else:
            console.print("  No configuration files found")

        console.print("\n[bold]Environment Overrides:[/bold]")
        if config_info["env_overrides"]:
            for env_var in config_info["env_overrides"]:
                console.print(f"  {env_var}")
        else:
            console.print("  None")

        console.print("\n[bold]Default Locations:[/bold]")
        for default_path in config_info["default_paths"]:
            console.print(f"  {default_path}")