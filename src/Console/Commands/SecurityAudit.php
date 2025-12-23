<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\Console\Commands;

use ArtisanPackUI\Security\Testing\CiCd\SecurityGate;
use ArtisanPackUI\Security\Testing\Performance\ImpactAnalyzer;
use ArtisanPackUI\Security\Testing\Performance\SecurityBenchmark;
use ArtisanPackUI\Security\Testing\Reporting\SecurityReportGenerator;
use ArtisanPackUI\Security\Testing\Scanners\ConfigurationScanner;
use ArtisanPackUI\Security\Testing\Scanners\DependencyScanner;
use ArtisanPackUI\Security\Testing\Scanners\OwaspScanner;
use Illuminate\Console\Command;

class SecurityAudit extends Command
{
    protected $signature = 'security:audit
                            {--format=json : Output format (json, html, sarif, junit, markdown)}
                            {--output= : Output file path}
                            {--benchmark : Include performance benchmarks}
                            {--no-fail : Do not exit with error code on findings}';

    protected $description = 'Run a comprehensive security audit with all scanners';

    public function handle(): int
    {
        $this->info('Starting comprehensive security audit...');
        $this->newLine();

        $startTime = microtime(true);
        $findings = [];

        // Run all scanners
        $this->task('OWASP Top 10 Scanner', function () use (&$findings) {
            $scanner = new OwaspScanner;
            $findings = array_merge($findings, $scanner->scan());

            return true;
        });

        $this->task('Dependency Scanner', function () use (&$findings) {
            $scanner = new DependencyScanner;
            $findings = array_merge($findings, $scanner->scan());

            return true;
        });

        $this->task('Configuration Scanner', function () use (&$findings) {
            $scanner = new ConfigurationScanner;
            $findings = array_merge($findings, $scanner->scan());

            return true;
        });

        // Optional performance benchmarks
        $benchmarkResults = [];
        if ($this->option('benchmark')) {
            $this->task('Performance Benchmarks', function () use (&$benchmarkResults) {
                $benchmark = new SecurityBenchmark;
                $benchmarkResults = $benchmark->runFullSuite();

                return true;
            });

            // Analyze performance impact
            $analyzer = new ImpactAnalyzer($benchmarkResults);
            $performanceFindings = $analyzer->analyze();
            $findings = array_merge($findings, $performanceFindings);
        }

        $duration = round(microtime(true) - $startTime, 2);

        // Generate report
        $report = new SecurityReportGenerator(
            projectName: config('app.name', 'Application'),
            version: config('app.version', '1.0.0')
        );

        $report->addFindings($findings)
            ->withMetadata([
                'auditDuration' => $duration,
                'benchmarksIncluded' => $this->option('benchmark'),
            ])
            ->sortBySeverity();

        $format = $this->option('format');
        $output = $report->generate($format);

        // Output results
        if ($outputPath = $this->option('output')) {
            $result = file_put_contents($outputPath, $output);
            if ($result === false) {
                $this->error("Failed to write report to: {$outputPath}");
            } else {
                $this->info("Report saved to: {$outputPath}");
            }
        }

        // Display results
        $this->displayResults($report->getSummary(), $benchmarkResults, $duration);

        // Run security gate
        $gate = new SecurityGate(
            maxCritical: (int) config('artisanpack.security.testing.gate.maxCritical', 0),
            maxHigh: (int) config('artisanpack.security.testing.gate.maxHigh', 0),
            maxMedium: (int) config('artisanpack.security.testing.gate.maxMedium', 10)
        );

        $gateResult = $gate->evaluate($findings, $benchmarkResults);

        $this->newLine();
        if ($gateResult->passed) {
            $this->info('Security audit passed!');
        } else {
            $this->error('Security audit failed!');
            foreach ($gateResult->failures as $failure) {
                $this->line("  - {$failure}");
            }
        }

        if ($this->option('no-fail')) {
            return self::SUCCESS;
        }

        return $gateResult->getExitCode();
    }

    /**
     * Run a task with visual feedback.
     */
    protected function task(string $title, callable $task): void
    {
        $this->output->write("  {$title}... ");

        try {
            $result = $task();
            $this->output->writeln($result ? '<fg=green>DONE</>' : '<fg=yellow>SKIPPED</>');
        } catch (\Exception $e) {
            $this->output->writeln('<fg=red>FAILED</>');
            $this->error("    Error: {$e->getMessage()}");
        }
    }

    /**
     * Display audit results.
     *
     * @param  array<string, mixed>  $summary
     * @param  array<\ArtisanPackUI\Security\Testing\Performance\BenchmarkResult>  $benchmarks
     */
    protected function displayResults(array $summary, array $benchmarks, float $duration): void
    {
        $this->newLine();
        $this->info("=== Security Audit Results ({$duration}s) ===");
        $this->newLine();

        // Findings summary
        $this->line('<fg=white;options=bold>Findings Summary:</>');
        $this->newLine();

        $rows = [];
        foreach ($summary['bySeverity'] as $severity => $count) {
            $color = match ($severity) {
                'critical' => 'red',
                'high' => 'yellow',
                'medium' => 'blue',
                'low' => 'cyan',
                default => 'gray',
            };
            $rows[] = ["<fg={$color}>".ucfirst($severity).'</>', $count];
        }
        $rows[] = ['<fg=white;options=bold>Total</>', "<fg=white;options=bold>{$summary['total']}</>"];

        $this->table(['Severity', 'Count'], $rows);

        // Category breakdown
        if (! empty($summary['byCategory'])) {
            $this->newLine();
            $this->line('<fg=white;options=bold>Findings by Category:</>');
            $this->newLine();

            $categoryRows = [];
            foreach ($summary['byCategory'] as $category => $count) {
                $categoryRows[] = [$category, $count];
            }

            $this->table(['Category', 'Count'], $categoryRows);
        }

        // Benchmark results
        if (! empty($benchmarks)) {
            $this->newLine();
            $this->line('<fg=white;options=bold>Performance Benchmarks:</>');
            $this->newLine();

            $benchmarkRows = [];
            foreach ($benchmarks as $result) {
                $benchmarkRows[] = $result->toTableRow();
            }

            $this->table(['Benchmark', 'With Security', 'Without', 'Overhead', 'Status'], $benchmarkRows);
        }
    }
}
