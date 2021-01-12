package ar.coders.tokenauth.bussiness.models;

import lombok.Data;

@Data
public class User {
    private String username;
    private String password;
    private String code;
}
