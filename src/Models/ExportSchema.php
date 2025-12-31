<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\Models;

use Illuminate\Database\Eloquent\Model;

class ExportSchema extends Model
{
    /**
     * The table associated with the model.
     */
    protected $table = 'export_schemas';

    /**
     * The attributes that are mass assignable.
     *
     * @var array<string>
     */
    protected $fillable = [
        'name',
        'category',
        'version',
        'format',
        'schema_definition',
        'field_mappings',
        'transformations',
        'is_default',
        'is_active',
    ];

    /**
     * The attributes that should be cast.
     *
     * @var array<string, string>
     */
    protected $casts = [
        'schema_definition' => 'array',
        'field_mappings' => 'array',
        'transformations' => 'array',
        'is_default' => 'boolean',
        'is_active' => 'boolean',
    ];

    /**
     * Scope for active schemas.
     *
     * @param  \Illuminate\Database\Eloquent\Builder<ExportSchema>  $query
     * @return \Illuminate\Database\Eloquent\Builder<ExportSchema>
     */
    public function scopeActive($query)
    {
        return $query->where('is_active', true);
    }

    /**
     * Scope for default schemas.
     *
     * @param  \Illuminate\Database\Eloquent\Builder<ExportSchema>  $query
     * @return \Illuminate\Database\Eloquent\Builder<ExportSchema>
     */
    public function scopeDefault($query)
    {
        return $query->where('is_default', true);
    }

    /**
     * Get schema for category and format.
     */
    public static function getForCategoryAndFormat(string $category, string $format): ?self
    {
        return static::active()
            ->where('category', $category)
            ->where('format', $format)
            ->orderByDesc('is_default')
            ->orderByDesc('version')
            ->first();
    }
}
