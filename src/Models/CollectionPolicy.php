<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\Models;

use Illuminate\Database\Eloquent\Model;

class CollectionPolicy extends Model
{
    /**
     * The table associated with the model.
     */
    protected $table = 'collection_policies';

    /**
     * The attributes that are mass assignable.
     *
     * @var array<string>
     */
    protected $fillable = [
        'name',
        'purpose',
        'allowed_fields',
        'required_fields',
        'conditional_fields',
        'prohibited_fields',
        'legal_basis',
        'consent_type',
        'minimization_rules',
        'is_active',
    ];

    /**
     * The attributes that should be cast.
     *
     * @var array<string, string>
     */
    protected $casts = [
        'allowed_fields' => 'array',
        'required_fields' => 'array',
        'conditional_fields' => 'array',
        'prohibited_fields' => 'array',
        'minimization_rules' => 'array',
        'is_active' => 'boolean',
    ];

    /**
     * Check if a field is allowed for this purpose.
     */
    public function isFieldAllowed(string $field): bool
    {
        // Check if explicitly prohibited
        if (in_array($field, $this->prohibited_fields ?? [])) {
            return false;
        }

        // If allowed_fields is set, field must be in it
        if (! empty($this->allowed_fields)) {
            return in_array($field, $this->allowed_fields);
        }

        return true;
    }

    /**
     * Check if a field is required for this purpose.
     */
    public function isFieldRequired(string $field): bool
    {
        return in_array($field, $this->required_fields ?? []);
    }

    /**
     * Check if consent is required for this purpose.
     */
    public function requiresConsent(): bool
    {
        return $this->consent_type !== 'not_required';
    }

    /**
     * Check if explicit consent is required.
     */
    public function requiresExplicitConsent(): bool
    {
        return $this->consent_type === 'explicit';
    }

    /**
     * Filter data to only allowed fields.
     *
     * @param  array<string, mixed>  $data
     * @return array<string, mixed>
     */
    public function filterData(array $data): array
    {
        return array_filter($data, fn ($key) => $this->isFieldAllowed($key), ARRAY_FILTER_USE_KEY);
    }

    /**
     * Validate that all required fields are present.
     *
     * @param  array<string, mixed>  $data
     * @return array<string>
     */
    public function getMissingRequiredFields(array $data): array
    {
        $required = $this->required_fields ?? [];

        return array_diff($required, array_keys($data));
    }

    /**
     * Scope for active policies.
     *
     * @param  \Illuminate\Database\Eloquent\Builder<CollectionPolicy>  $query
     * @return \Illuminate\Database\Eloquent\Builder<CollectionPolicy>
     */
    public function scopeActive($query)
    {
        return $query->where('is_active', true);
    }

    /**
     * Get policy for a purpose.
     */
    public static function getForPurpose(string $purpose): ?self
    {
        return static::active()
            ->where('purpose', $purpose)
            ->first();
    }
}
