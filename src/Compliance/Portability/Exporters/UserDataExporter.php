<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\Compliance\Portability\Exporters;

use Illuminate\Support\Collection;

class UserDataExporter extends BaseExporter
{
    protected string $category = 'profile';

    /**
     * Get exporter name.
     */
    public function getName(): string
    {
        return 'user_profile';
    }

    /**
     * Get exportable data for user.
     */
    public function getData(int $userId): Collection
    {
        $userModel = config('auth.providers.users.model');
        $user = $userModel::find($userId);

        if (! $user) {
            return collect();
        }

        return collect([$user]);
    }

    /**
     * Get data schema.
     *
     * @return array<string, mixed>
     */
    public function getSchema(): array
    {
        return [
            'type' => 'object',
            'properties' => [
                'id' => ['type' => 'integer', 'description' => 'User ID'],
                'name' => ['type' => 'string', 'description' => 'Full name'],
                'email' => ['type' => 'string', 'format' => 'email', 'description' => 'Email address'],
                'email_verified_at' => ['type' => 'string', 'format' => 'date-time', 'description' => 'Email verification date'],
                'created_at' => ['type' => 'string', 'format' => 'date-time', 'description' => 'Account creation date'],
                'updated_at' => ['type' => 'string', 'format' => 'date-time', 'description' => 'Last update date'],
            ],
        ];
    }

    /**
     * Transform a single item.
     *
     * @return array<string, mixed>
     */
    protected function transformItem(mixed $item): array
    {
        $data = parent::transformItem($item);

        // Remove sensitive fields
        unset($data['password'], $data['remember_token']);

        return $data;
    }
}
