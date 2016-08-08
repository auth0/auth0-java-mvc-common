package com.auth0;

import com.auth0.authentication.result.UserIdentity;
import com.auth0.authentication.result.UserProfile;
import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;
import org.apache.commons.lang3.builder.ToStringBuilder;

import java.io.Serializable;
import java.security.Principal;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;

/**
 * Convenience wrapper around the Auth0 UserProfile
 * object (GSON) and implements Principal interface
 */
public class Auth0User implements Principal, Serializable {

    private static final long serialVersionUID = 2371882820082543721L;

    private String userId;
    private String name;
    private String nickname;
    private String picture;
    private String email;
    private boolean emailVerified;
    private String givenName;
    private String familyName;
    private Map<String, Object> userMetadata;
    private Map<String, Object> appMetadata;
    private Date createdAt;
    private List<UserIdentity> identities;
    private Map<String, Object> extraInfo;
    private List<String> roles = new ArrayList();
    private List<String> groups = new ArrayList();

    public Auth0User(final UserProfile userProfile) {
        // for now, copy out attributes from userProfile
        this.userId = userProfile.getId();
        this.name = userProfile.getName();
        this.nickname = userProfile.getNickname();
        this.picture = userProfile.getPictureURL();
        this.email = userProfile.getEmail();
        this.emailVerified = userProfile.isEmailVerified();
        this.givenName = userProfile.getGivenName();
        this.familyName = userProfile.getFamilyName();
        this.userMetadata = userProfile.getUserMetadata();
        this.appMetadata = userProfile.getAppMetadata();
        this.createdAt = userProfile.getCreatedAt();
        this.identities = userProfile.getIdentities();
        this.extraInfo = userProfile.getExtraInfo();

        if (extraInfo != null && extraInfo.containsKey("roles")) {
            roles = (List<String>) extraInfo.get("roles");
        }
        if (extraInfo != null && extraInfo.containsKey("groups")) {
            groups = (List<String>) extraInfo.get("groups");
        }

    }

    public String getUserId() {
        return userId;
    }

    @Override
    public String getName() {
        return name;
    }

    public String getNickname() {
        return nickname;
    }

    public String getPicture() {
        return picture;
    }

    public String getEmail() {
        return email;
    }

    public boolean isEmailVerified() {
        return emailVerified;
    }

    public String getGivenName() {
        return givenName;
    }

    public String getFamilyName() {
        return familyName;
    }

    public Map<String, Object> getUserMetadata() {
        return userMetadata;
    }

    public Map<String, Object> getAppMetadata() {
        return appMetadata;
    }

    public Date getCreatedAt() {
        return createdAt;
    }

    public List<String> getRoles() {
        return roles;
    }

    public List<String> getGroups() {
        return groups;
    }

    public List<UserIdentity> getIdentities() {
        return identities;

    }

    public Map<String, Object> getExtraInfo() {
        return extraInfo;
    }



    public boolean equals(Object obj) {
        if (obj == null) { return false; }
        if (obj == this) { return true; }
        if (obj.getClass() != getClass()) {
            return false;
        }
        Auth0User rhs = (Auth0User) obj;
        return new EqualsBuilder()
                .appendSuper(super.equals(obj))
                .append(userId, rhs.userId)
                .isEquals();
    }

    public int hashCode() {
        return new HashCodeBuilder(17, 37).
                append(userId).
                toHashCode();
    }

    public String toString() {
        return new ToStringBuilder(this).
                append("userId", userId).
                append("name", name).
                append("email", email).
                toString();
    }

}
