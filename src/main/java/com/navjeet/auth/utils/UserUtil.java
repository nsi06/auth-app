package com.navjeet.auth.utils;

import java.util.UUID;

public class UserUtil {
    public static UUID parseUUID(String uuid) {
        return UUID.fromString(uuid);
    }
}
