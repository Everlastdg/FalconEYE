"""CLI command implementations."""

import asyncio
from pathlib import Path
from typing import Optional
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.panel import Panel

from ...infrastructure.di.container import DIContainer
from ...infrastructure.config.config_loader import ConfigLoader
from ...infrastructure.presentation.error_presenter import ErrorPresenter
from ...application.commands.index_codebase import IndexCodebaseCommand
from ...application.commands.review_file import ReviewFileCommand
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
        # Directory - review all files from ALL detected languages
        
        # Detect all languages in the codebase
        try:
            all_languages = container.language_detector.detect_all_languages(path)
            console.print(f"[cyan]Detected languages: {', '.join(all_languages)}[/cyan]")
        except Exception:
            # Fallback to single language
            all_languages = [language]
        
        # Collect files from all detected languages
        files = []
        for lang in all_languages:
            extensions = container.language_detector.LANGUAGE_EXTENSIONS.get(lang, [])
            for ext in extensions:
                files.extend(list(path.rglob(f"*{ext}")))
        
        # Remove duplicates
        files = list(set(files))

        if not files:
            console.print(f"[yellow]No source files found in {path}[/yellow]")
            return

        # Create aggregate review
        from ...domain.models.security import SecurityReview
        aggregate_review = SecurityReview.create(
            codebase_path=str(path),
            language=language,
        )

        # Review each file
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            console=console,
        ) as progress:
            task = progress.add_task(f"Analyzing {len(files)} files...", total=len(files))

            for file_path in files:
                try:
                    progress.update(task, description=f"Analyzing {file_path.name}...")

                    # Detect language for this specific file
                    file_language = container.language_detector.detect_language(file_path)
                    file_system_prompt = container.get_system_prompt(file_language)

                    command = ReviewFileCommand(
                        file_path=file_path,
                        language=file_language,
                        system_prompt=file_system_prompt,
                        validate_findings=validate,
                        top_k_context=top_k,
                    )

                    review = asyncio.run(container.review_file_handler.handle(command))

                    # Add findings to aggregate
                    for finding in review.findings:
                        aggregate_review.add_finding(finding)

                    progress.advance(task)

                except KeyboardInterrupt:
                    progress.update(task, description="[yellow]Analysis cancelled")
                    error_msg = ErrorPresenter.present(KeyboardInterrupt(), verbose=verbose)
                    console.print(f"\n{error_msg}")
                    raise SystemExit(1)

                except Exception as e:
                    # For directory scan, show warning and continue
                    console.print(f"\n[yellow]Warning: Failed to analyze {file_path.name}[/yellow]")
                    if verbose:
                        error_msg = ErrorPresenter.present(e, verbose=True)
                        console.print(error_msg)
                    progress.advance(task)
                    continue

            progress.update(task, description="[green]Analysis complete!")

        review = aggregate_review

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