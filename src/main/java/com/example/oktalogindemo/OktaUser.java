package com.example.oktalogindemo;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.oidc.AddressStandardClaim;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;

import java.util.Collection;

public class OktaUser extends DefaultOidcUser implements User
{
    public static final String ROLE_USER = "ROLE_USER";
    public static final String MEMBER_OF_CLAIM = "member_of";

    public static final String USER_ID_CLAIM = "preferred_username";
    private static final String FIRST_NAME_CLAIM = "given_name";
    private static final String LAST_NAME_CLAIM = "family_name";

    public static final String VHI_PARTNER_ID = "vhiPartnerID";

    public OktaUser(final Collection<? extends GrantedAuthority> authorities, final OidcIdToken idToken,
                    final OidcUserInfo userInfo, final String nameAttributeKey)
    {
        super(authorities, idToken, userInfo, nameAttributeKey);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || this.getClass() != obj.getClass()) {
            return false;
        }

        OktaUser that = (OktaUser) obj;
        return this.getName().equals(that.getName());
    }

    @Override
    public int hashCode() {
        return this.getName().hashCode();
    }

    @Override
    public String getUserId() {
        return getClaim(USER_ID_CLAIM);
    }

    @Override
    public String getFirstName() {
        return getClaim(FIRST_NAME_CLAIM);
    }

    @Override
    public String getLastName() {
        return getClaim(LAST_NAME_CLAIM);
    }

    @Override
    public String getVhiPartnerId() {
        return getClaim(VHI_PARTNER_ID);
    }

    @Override
    public AddressStandardClaim getAddress() {
        return super.getAddress();
    }
}
