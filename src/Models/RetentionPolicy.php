<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\Models;

use Illuminate\Database\Eloquent\Model;

class RetentionPolicy extends Model
{
    /**
     * The table associated with the model.
     */
    protected $table = 'retention_policies';

    /**
     * The attributes that are mass assignable.
     *
     * @var array<string>
     */
    protected $fillable = [
        'name',
        'description',
        'model_class',
        'data_category',
        'retention_days',
        'legal_basis',
        'deletion_strategy',
        'archive_location',
        'conditions',
        'exceptions',
        'notification_days',
        'is_active',
        'created_by',
    ];

    /**
     * The attributes that should be cast.
     *
     * @var array<string, string>
     */
    protected $casts = [
        'conditions' => 'array',
        'exceptions' => 'array',
        'is_active' => 'boolean',
    ];

    /**
     * Check if retention period is indefinite.
     */
    public function isIndefinite(): bool
    {
        return $this->retention_days === null;
    }

    /**
     * Get the expiration date for data created at a given time.
     */
    public function getExpirationDate(\DateTimeInterface $createdAt): ?\DateTimeInterface
    {
        if ($this->isIndefinite()) {
            return null;
        }

        return \Carbon\Carbon::parse($createdAt)->addDays($this->retention_days);
    }

    /**
     * Check if a record should be deleted based on its created date.
     */
    public function shouldDelete(\DateTimeInterface $createdAt): bool
    {
        $expirationDate = $this->getExpirationDate($createdAt);

        return $expirationDate !== null && $expirationDate->isPast();
    }

    /**
     * Scope for active policies.
     *
     * @param  \Illuminate\Database\Eloquent\Builder<RetentionPolicy>  $query
     * @return \Illuminate\Database\Eloquent\Builder<RetentionPolicy>
     */
    public function scopeActive($query)
    {
        return $query->where('is_active', true);
    }

    /**
     * Get policy for a model class.
     */
    public static function getForModel(string $modelClass): ?self
    {
        return static::active()
            ->where('model_class', $modelClass)
            ->first();
    }

    /**
     * Get policies for a data category.
     *
     * @return \Illuminate\Database\Eloquent\Collection<int, RetentionPolicy>
     */
    public static function getForCategory(string $category): \Illuminate\Database\Eloquent\Collection
    {
        return static::active()
            ->where('data_category', $category)
            ->get();
    }
}
