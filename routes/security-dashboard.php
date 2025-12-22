<?php

declare(strict_types=1);

use ArtisanPackUI\Security\Livewire\SecurityDashboard;
use ArtisanPackUI\Security\Livewire\SecurityEventList;
use ArtisanPackUI\Security\Livewire\SecurityStats;
use Illuminate\Support\Facades\Route;

$prefix = config('artisanpack.security.eventLogging.dashboard.routePrefix', 'security');
$middleware = config('artisanpack.security.eventLogging.dashboard.middleware', ['web', 'auth']);

Route::middleware($middleware)
    ->prefix($prefix)
    ->name('security.')
    ->group(function () {
        Route::get('/dashboard', SecurityDashboard::class)->name('dashboard');
        Route::get('/events', SecurityEventList::class)->name('events');
        Route::get('/stats', SecurityStats::class)->name('stats');
    });
