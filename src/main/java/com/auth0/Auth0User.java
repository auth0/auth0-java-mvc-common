package com.auth0;

import com.auth0.authentication.result.UserIdentity;
import com.auth0.authentication.result.UserProfile;
import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;
import org.apache.commons.lang3.builder.ToStringBuilder;

import java.io.Serializable;
import java.security.Principal;
import java.util.*;

/**
 * Auth0 User Profile information. Implements Principal interface -
 * represents the abstract notion of a principal, which can be used
 * to represent any entity, such as an individual or login id.
 */
public class Auth0User implements Principal, Serializable {

    private static final long serialVersionUID = 2371882820082543721L;

    /**
     * The userId of the Auth0 normalized user profile
     */
    private final String userId;

    /**
     * The name assigned to the user profile
     */
    private final String name;

    /**
     * The nickname assigned to the user profile
     */
    private final String nickname;

    /**
     * The picture (gravatar) of the user profile
     */
    private final String picture;

    /**
     * The email assigned to the user profile
     */
    private final String email;

    /**
     * The email verified or not
     */
    private final boolean emailVerified;

    /**
     * The given name assigned to the user profile
     */
    private final String givenName;

    /**
     * The family name assigned to the user profile
     */
    private final String familyName;

    /**
     * The metadata objects can be used to store additional User Profile information.
     * The user_metadata object should be used to store user attributes, such as user preferences,
     * that don't impact what a user can access
     */
    private final Map<String, Object> userMetadata;

    /**
     * The metadata objects can be used to store additional User Profile information.
     * The app_metadata object should be used for user attributes, such as a support plan, security roles,
     * or access control groups, which can impact how an application functions and/or what the user can access.
     */
    private final Map<String, Object> appMetadata;

    /**
     * The created at date
     */
    private final Date createdAt;

    /**
     * List of the identities from a Identity Provider associated to the user.
     */
    private final List<UserIdentity> identities;

    /**
     * Extra information of the profile that is not part of the normalized profile
     * A map with user's extra information found in the profile
     */
    private final Map<String, Object> extraInfo;

    /**
     * The Roles assigned to the user profile
     */
    private final List<String> roles;

    /**
     * The Groups assigned to the user profile
     */
    private final List<String> groups;


    /**
     * User Profile and Principal object
     *
     * @param userProfile the User Profile from which to extract the user profile attributes
     */
    public Auth0User(final UserProfile userProfile) {
        this(userProfile.getId(), userProfile.getName(), userProfile.getNickname(), userProfile.getPictureURL(), userProfile.getEmail(),
        userProfile.isEmailVerified(), userProfile.getGivenName(), userProfile.getFamilyName(), userProfile.getCreatedAt(), userProfile.getIdentities(),
        userProfile.getUserMetadata(), userProfile.getAppMetadata(), userProfile.getExtraInfo());
    }

    /**
     *  User Profile and Principal object
     * @param userId
     * @param name
     * @param nickname
     * @param picture
     * @param email
     * @param emailVerified
     * @param givenName
     * @param familyName
     * @param createdAt
     * @param identities
     * @param userMetadata
     * @param appMetadata
     * @param extraInfo
     */
    public Auth0User(final String userId, final String name, final String nickname, final String picture, final String email,
                     final boolean emailVerified, final String givenName, final String familyName, final Date createdAt, final List<UserIdentity> identities,
                     final Map<String, Object> userMetadata, final Map<String, Object> appMetadata, final Map<String, Object> extraInfo) {
        this.userId = userId;
        this.name = name;
        this.nickname = nickname;
        this.picture = picture;
        this.email = email;
        this.emailVerified = emailVerified;
        this.givenName = givenName;
        this.familyName = familyName;
        this.createdAt = createdAt;
        this.identities = identities != null ? new ArrayList<>(identities) : new ArrayList<UserIdentity>();
        this.userMetadata = userMetadata != null ? new HashMap<>(userMetadata) : new HashMap<String, Object>();
        this.appMetadata = appMetadata != null ? new HashMap<>(appMetadata) : new HashMap<String, Object>();
        this.extraInfo = extraInfo != null ? new HashMap<>(extraInfo) : new HashMap<String, Object>();
        this.roles = extraInfo != null && extraInfo.containsKey("roles") ? new ArrayList<>((List<String>)extraInfo.get("roles")) : new ArrayList<String>();
        this.groups = extraInfo != null && extraInfo.containsKey("groups") ? new ArrayList<>((List<String>)extraInfo.get("groups")) : new ArrayList<String>();
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

    /**
     * @return createdAt date or null
     */
    public Date getCreatedAt() {
        return createdAt != null ? new Date(createdAt.getTime()) : null;
    }

    public List<UserIdentity> getIdentities() {
        return Collections.unmodifiableList(identities);
    }

    public Map<String, Object> getUserMetadata() {
        return Collections.unmodifiableMap(userMetadata);
    }

    public Map<String, Object> getAppMetadata() {
        return Collections.unmodifiableMap(appMetadata);
    }

    public Map<String, Object> getExtraInfo() {
        return Collections.unmodifiableMap(extraInfo);
    }

    public List<String> getRoles() {
        return Collections.unmodifiableList(roles);
    }

    public List<String> getGroups() {
        return Collections.unmodifiableList(groups);
    }


    public boolean equals(Object obj) {
        if (obj == null) { return false; }
        if (obj == this) { return true; }
        if (obj.getClass() != getClass()) {
            return false;
        }
        final Auth0User rhs = (Auth0User) obj;
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
