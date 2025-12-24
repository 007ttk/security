<?php

namespace Tests\Models;

use ArtisanPackUI\Security\Concerns\HasRoles;
use Illuminate\Foundation\Auth\User;

class TestUser extends User
{
    use HasRoles;

    protected $table = 'users';

    protected $fillable = [
        'id',
        'name',
        'email',
        'password',
    ];
}
