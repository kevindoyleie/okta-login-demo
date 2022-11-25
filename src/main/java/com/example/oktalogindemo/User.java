package com.example.oktalogindemo;

import org.springframework.security.oauth2.core.oidc.AddressStandardClaim;

public interface User
{
    String getUserId();
    String getFirstName();
    String getLastName();
    String getVhiPartnerId();
    AddressStandardClaim getAddress();
}
