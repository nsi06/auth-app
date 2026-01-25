package com.navjeet.auth.services;

import com.navjeet.auth.dtos.UserDto;

public interface AuthService {
    UserDto registerUser(UserDto userDto);
}
