<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\Console\Commands;

use ArtisanPackUI\Security\Compliance\Reporting\ReportGenerator;
use Illuminate\Console\Command;

class GenerateComplianceReport extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'compliance:report
                            {type=compliance_status : Report type to generate}
                            {--format=json : Output format (json, html, csv)}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Generate a compliance report';

    public function __construct(protected ReportGenerator $reportGenerator)
    {
        parent::__construct();
    }

    /**
     * Execute the console command.
     */
    public function handle(): int
    {
        $type = $this->argument('type');
        $format = $this->option('format');

        $this->info("Generating {$type} report...");

        try {
            $report = $this->reportGenerator->generate($type);
            $path = $this->reportGenerator->export($report, $format);

            $this->info("Report generated: {$path}");

            return 0;
        } catch (\Exception $e) {
            $this->error("Failed to generate report: {$e->getMessage()}");

            return 1;
        }
    }
}
