<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\Models;

use Illuminate\Database\Eloquent\Model;

class ComplianceScore extends Model
{
    /**
     * The table associated with the model.
     */
    protected $table = 'compliance_scores';

    /**
     * The attributes that are mass assignable.
     *
     * @var array<string>
     */
    protected $fillable = [
        'overall_score',
        'regulation',
        'category_scores',
        'findings',
        'recommendations',
        'calculated_at',
        'next_calculation_at',
        'calculated_by',
    ];

    /**
     * The attributes that should be cast.
     *
     * @var array<string, string>
     */
    protected $casts = [
        'overall_score' => 'decimal:2',
        'category_scores' => 'array',
        'findings' => 'array',
        'recommendations' => 'array',
        'calculated_at' => 'datetime',
        'next_calculation_at' => 'datetime',
    ];

    /**
     * Get the compliance grade based on score.
     */
    public function getGrade(): string
    {
        if ($this->overall_score >= 90) {
            return 'A';
        }
        if ($this->overall_score >= 80) {
            return 'B';
        }
        if ($this->overall_score >= 70) {
            return 'C';
        }
        if ($this->overall_score >= 60) {
            return 'D';
        }

        return 'F';
    }

    /**
     * Check if score is passing.
     */
    public function isPassing(): bool
    {
        return $this->overall_score >= 70;
    }

    /**
     * Get score for a specific category.
     */
    public function getCategoryScore(string $category): ?float
    {
        return $this->category_scores[$category] ?? null;
    }

    /**
     * Scope for a specific regulation.
     *
     * @param  \Illuminate\Database\Eloquent\Builder<ComplianceScore>  $query
     * @return \Illuminate\Database\Eloquent\Builder<ComplianceScore>
     */
    public function scopeForRegulation($query, string $regulation)
    {
        return $query->where('regulation', $regulation);
    }

    /**
     * Get the latest score for a regulation.
     */
    public static function getLatest(?string $regulation = null): ?self
    {
        $query = static::query();

        if ($regulation) {
            $query->forRegulation($regulation);
        } else {
            $query->where('regulation', 'all');
        }

        return $query->orderByDesc('calculated_at')->first();
    }

    /**
     * Get historical scores for trending.
     *
     * @return \Illuminate\Database\Eloquent\Collection<int, ComplianceScore>
     */
    public static function getHistory(?string $regulation = null, int $limit = 30): \Illuminate\Database\Eloquent\Collection
    {
        $query = static::query();

        if ($regulation) {
            $query->forRegulation($regulation);
        } else {
            $query->where('regulation', 'all');
        }

        return $query->orderByDesc('calculated_at')
            ->limit($limit)
            ->get();
    }
}
