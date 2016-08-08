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
 * <p>
 * Examples of query param:
 * <p>
 * queryString = "nonce=B4AD596E418F7CE02A703B42F60BAD8F";
 * queryString = "externalRedirectUrl=http://localhost:3099/callback";
 * queryString = "nonce=B4AD596E418F7CE02A703B42F60BAD8F&externalRedirectUrl=http://localhost:3099/callback";
 * <p>
 * Useful where you wish to get a given value for a key/pair out, or replace / remove a key/value pair etc
 */
public class QueryParamUtils {

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
