package com.auth0;

import org.apache.commons.lang3.Validate;
import org.apache.http.NameValuePair;
import org.apache.http.client.utils.URLEncodedUtils;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * Convenience functions for querying / manipulating queryParams.
 * Useful where you wish to get a given value for a key/pair out,
 * or replace / remove a key/value pair
 */
public class QueryParamUtils {

    /**
     * Add or replace the given key value pair in the supplied query param
     *
     * @param queryParams the query param
     * @param key the key whose corresponding value is to be added or replaced
     * @param value the value to add or replace corresponding to given key
     * @return updated query param with added or updated key value pair
     */
    public static String addOrReplaceInQueryParams(final String queryParams, final String key, final String value) {
        Validate.notNull(queryParams);
        Validate.notNull(key);
        Validate.notNull(value);
        final StringBuilder builder = new StringBuilder();
        final String updatedQueryParams = removeFromQueryParams(queryParams, key);
        if (updatedQueryParams.isEmpty()) {
            builder.append(key).append("=").append(value);
        } else {
            builder.append(updatedQueryParams).append("&").append(key).append("=").append(value);
        }
        return builder.toString();
    }

    /**
     * Get the value corresponding to the supplied key from the supplied query param
     *
     * @param queryParams the query param
     * @param key the key whose value should be returned if present
     * @return the value corresponding to supplied key or null if not present
     */
    public static String parseFromQueryParams(final String queryParams, final String key) {
        Validate.notNull(queryParams);
        Validate.notNull(key);
        final List<NameValuePair> params = URLEncodedUtils.parse(queryParams, StandardCharsets.UTF_8);
        for (final NameValuePair param : params) {
            if (key.equals(param.getName())) {
                return param.getValue();
            }
        }
        return null;
    }

    /**
     * Indicates whether the supplied key already exists as a key value pair in the supplied query param
     *
     * @param queryParams the query param
     * @param key the key to search for
     * @return boolean whether the key does already exist in supplied query param
     */
    public static boolean keyInQueryParams(final String queryParams, final String key) {
        Validate.notNull(queryParams);
        Validate.notNull(key);
        final List<NameValuePair> params = URLEncodedUtils.parse(queryParams, StandardCharsets.UTF_8);
        for (final NameValuePair param : params) {
            if (key.equals(param.getName())) {
                return true;
            }
        }
        return false;
    }

    /**
     * Remove the given key value pair from the supplied query param
     *
     * @param queryParams the query param
     * @param key the key whose corresponding value is to be added or replaced
     * @return updated query param with removed (if previously present) key value pair
     */
    public static String removeFromQueryParams(final String queryParams, final String key) {
        Validate.notNull(queryParams);
        Validate.notNull(key);
        final List<NameValuePair> params = URLEncodedUtils.parse(queryParams, StandardCharsets.UTF_8);
        final List<NameValuePair> newParams = new ArrayList<>();
        for (final NameValuePair param : params) {
            if (!key.equals(param.getName())) {
                newParams.add(param);
            }
        }
        final String newQueryStringEncoded = URLEncodedUtils.format(newParams, StandardCharsets.UTF_8);
        try {
            final String newQueryStringDecoded = URLDecoder.decode(newQueryStringEncoded, StandardCharsets.UTF_8.toString());
            return newQueryStringDecoded;
        } catch (UnsupportedEncodingException e) {
            throw new IllegalStateException("Failed to decode query param " + e.getLocalizedMessage());
        }
    }
}
