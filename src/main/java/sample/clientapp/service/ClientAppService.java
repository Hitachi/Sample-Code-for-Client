package sample.clientapp.service;

import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URLEncoder;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import sample.clientapp.ClientSession;
import sample.clientapp.TokenResponse;
import sample.clientapp.config.ClientAppConfiguration;
import sample.clientapp.config.OauthConfiguration;
import sample.clientapp.jwt.IdToken;
import sample.clientapp.jwt.JsonWebToken;
import sample.clientapp.util.JsonUtil;
import sample.clientapp.util.OauthUtil;

@Service
public class ClientAppService {

    private static final Logger logger = LoggerFactory.getLogger(ClientAppService.class);

    @Autowired
    ClientAppConfiguration clientConfig;

    @Autowired
    OauthConfiguration oauthConfig;

    @Autowired
    RestTemplate restTemplate;

    @Autowired
    ClientSession clientSession;

    public String getAuthorizationUrl(String scope) {
        StringBuilder authorizationUrl = new StringBuilder();
        authorizationUrl.append(clientConfig.getAuthorizationEndpoint());

        String redirectUrl;
        try {
            redirectUrl = URLEncoder.encode(generateRedirectUri(), "UTF-8");
            if (scope != null && !scope.isEmpty())
                scope = URLEncoder.encode(scope, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            return "";
        }

        if (scope != null && !scope.isEmpty()) {
            authorizationUrl.append("?response_type=code").append("&client_id=").append(clientConfig.getClientId())
                    .append("&redirect_uri=").append(redirectUrl).append("&scope=").append(scope);
        } else {
            authorizationUrl.append("?response_type=code").append("&client_id=").append(clientConfig.getClientId())
                    .append("&redirect_uri=").append(redirectUrl);
        }

        if (oauthConfig.isState()) {
            String state = UUID.randomUUID().toString();
            clientSession.setState(state);
            authorizationUrl.append("&state=").append(state);
        }

        if (oauthConfig.isNonce()) {
            String nonce = UUID.randomUUID().toString();
            clientSession.setNonce(nonce);
            authorizationUrl.append("&nonce=").append(nonce);
        }

        if (oauthConfig.isPkce()) {
            String codeVerifier = OauthUtil.generateCodeVerifier();
            String codeChallenge = OauthUtil.generateCodeChallenge(codeVerifier);
            authorizationUrl.append("&code_challenge_method=S256&code_challenge=").append(codeChallenge);
            clientSession.setCodeVerifier(codeVerifier);
        }

        if (oauthConfig.isFormPost()) {
            authorizationUrl.append("&response_mode=form_post");
        }

        return authorizationUrl.toString();
    }

    public TokenResponse requestToken(String authorizationCode) {
        StringBuilder tokenRequestUrl = new StringBuilder();
        tokenRequestUrl.append(clientConfig.getTokenEndpoint());

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        headers.add("Authorization",
                "Basic " + OauthUtil.encodeToBasicClientCredential(clientConfig.getClientId(), clientConfig.getClientSecret()));

        MultiValueMap<String, String> params = new LinkedMultiValueMap<String, String>();
        params.add("code", authorizationCode);
        params.add("grant_type", "authorization_code");
        params.add("redirect_uri", generateRedirectUri());

        if (oauthConfig.isPkce()) {

            params.add("code_verifier", clientSession.getCodeVerifier());
        }

        RequestEntity<?> req = new RequestEntity<>(params, headers, HttpMethod.POST, URI.create(tokenRequestUrl.toString()));
        TokenResponse token = null;
        try {
            printRequest("Token Request", req);

            ResponseEntity<TokenResponse> res = restTemplate.exchange(req, TokenResponse.class);
            token = res.getBody();
            printResponse("Token Response", res);

        } catch (HttpClientErrorException e) {
            printClientError("Token Response", e);
        }

        return token;
    }

    public String processAuthorizationCodeGrant(String code, String state) {
        // check state before token request
        if (oauthConfig.isState()) {
            if (state == null || !state.equals(clientSession.getState())) {
                // state check failure. Write error handling here.
                logger.error("state check NG");
                return "gettoken";
            } else {
                logger.debug("state check OK");
                clientSession.setState(null);
            }
        }

        TokenResponse token = requestToken(code);
        if (token == null) {
            return "gettoken";
        }

        // check nonce after ID token is obtained
        if (oauthConfig.isNonce() && token.getIdToken() != null) {
            IdToken idToken = JsonWebToken.parse(token.getIdToken(), IdToken.class);
            if (idToken.getNonce() == null || !idToken.getNonce().equals(clientSession.getNonce())) {
                // nonce check failure. Write error handling here.
                logger.error("nonce check NG\n");
                return "gettoken";
            } else {
                logger.debug("nonce check OK\n");
                clientSession.setNonce(null);
            }
        }

        clientSession.setTokensFromTokenResponse(token);

        return "gettoken";
    }

    public TokenResponse refreshToken(String refreshToken) {
        StringBuilder tokenRequestUrl = new StringBuilder();
        tokenRequestUrl.append(clientConfig.getTokenEndpoint());

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        headers.add("Authorization",
                "Basic " + OauthUtil.encodeToBasicClientCredential(clientConfig.getClientId(), clientConfig.getClientSecret()));

        MultiValueMap<String, String> params = new LinkedMultiValueMap<String, String>();
        params.add("grant_type", "refresh_token");
        params.add("refresh_token", refreshToken);

        RequestEntity<?> req = new RequestEntity<>(params, headers, HttpMethod.POST, URI.create(tokenRequestUrl.toString()));
        TokenResponse token = null;
        printRequest("Refresh Request", req);

        try {
            ResponseEntity<TokenResponse> res = restTemplate.exchange(req, TokenResponse.class);
            token = res.getBody();
            printResponse("Refresh Response", res);
        } catch (HttpClientErrorException e) {
            printClientError("Refresh Response", e);
        }

        return token;
    }

    public void revokeToken(String refreshToken) {
        StringBuilder revokeUrl = new StringBuilder();
        revokeUrl.append(clientConfig.getRevokeEndpoint());

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        headers.add("Authorization",
                "Basic " + OauthUtil.encodeToBasicClientCredential(clientConfig.getClientId(), clientConfig.getClientSecret()));

        MultiValueMap<String, String> params = new LinkedMultiValueMap<String, String>();
        params.add("token", refreshToken);
        params.add("token_type_hint", "refresh_token");

        RequestEntity<?> req = new RequestEntity<>(params, headers, HttpMethod.POST, URI.create(revokeUrl.toString()));

        printRequest("Revoke Request", req);

        try {
            restTemplate.exchange(req, Object.class);
        } catch (HttpClientErrorException e) {
            printClientError("Revoke Response", e);

        }
    }

    public String callApi(String url, String accessToken) {
        HttpHeaders headers = new HttpHeaders();
        if (accessToken != null) {
            headers.setBearerAuth(accessToken);
        }

        RequestEntity<?> req = new RequestEntity<>(headers, HttpMethod.GET, URI.create(url));
        printRequest("Call API", req);
        String response = null;
        try {
            ResponseEntity<String> res = restTemplate.exchange(req, String.class);
            response = res.getBody();
            printResponse("Call API", res);
        } catch (HttpClientErrorException e) {
            printClientError("Call API", e);
            response = e.getStatusCode().toString();
        }

        return response;
    }

    private String generateRedirectUri() {
        String redirectUri = ServletUriComponentsBuilder.fromCurrentRequest().replacePath("/gettoken").replaceQuery(null)
                .toUriString();
        return redirectUri;
    }

    private void printRequest(String msg, RequestEntity<?> req) {
        Map<String, Object> message = new HashMap<>();
        message.put("method", req.getMethod().toString());
        message.put("url", req.getUrl().toString());
        message.put("headers", req.getHeaders());
        if (req.hasBody()) {
            message.put("body", req.getBody());
        }
        logger.debug("ReqeustType=\"" + msg + "\" RequestInfo=" + JsonUtil.marshal(message, false));
        return;
    }

    private void printResponse(String responseType, ResponseEntity<?> resp) {
        Map<String, Object> message = new HashMap<>();
        message.put("status", resp.getStatusCode().toString());
        message.put("headers", resp.getHeaders());
        message.put("body", resp.getBody());
        logger.debug("ResponseType=\"" + responseType + "\" ResponseInfo=" + JsonUtil.marshal(message, false));
        return;
    }

    private void printClientError(String errorType, HttpClientErrorException e) {
        Map<String, Object> message = new HashMap<>();
        message.put("status", e.getStatusCode().toString());
        message.put("headers", e.getResponseHeaders());
        message.put("body", e.getResponseBodyAsString());
        logger.error("ErrorType=\"" + errorType + "\" ResponseInfo=" + JsonUtil.marshal(message, false));

    }

}
