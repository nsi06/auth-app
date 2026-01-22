package com.navjeet.auth.mappers;

import com.navjeet.auth.dtos.UserDto;
import com.navjeet.auth.entities.User;
import org.mapstruct.Mapper;

@Mapper(componentModel = "spring")
public interface UserMapper {
    UserDto toDto(User user);
    User toEntity(UserDto userDto);
}
