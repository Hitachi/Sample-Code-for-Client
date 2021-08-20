package sample.clientapp;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URLEncoder;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import javax.servlet.http.HttpSession;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

@Controller
public class ClientAppController {

    private static final Logger logger = LoggerFactory.getLogger(ClientAppController.class);
    @Autowired
    HttpSession session;

    @Autowired
    ClientAppConfiguration clientConfig;

    @Autowired
    OauthConfiguration oauthConfig;

    @Autowired
    RestTemplate restTemplate;

    private String getAuthorizationUrl(String scope) {
        StringBuilder authorizationUrl = new StringBuilder();
        authorizationUrl.append(clientConfig.getAuthorizationEndpoint());

        String redirectUrl;
        try {
            redirectUrl = URLEncoder.encode(clientConfig.getClientappUrl() + "/gettoken", "UTF-8");
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
            session.setAttribute("state", state);
            authorizationUrl.append("&state=").append(state);
        }

        if (oauthConfig.isNonce()) {
            String nonce = UUID.randomUUID().toString();
            session.setAttribute("nonce", nonce);
            authorizationUrl.append("&nonce=").append(nonce);
        }

        if (oauthConfig.isPkce()) {
            String codeVerifier = OauthUtil.generateCodeVerifier();
            session.setAttribute("codeVerifier", codeVerifier);
            String codeChallenge = OauthUtil.generateCodeChallenge(codeVerifier);
            authorizationUrl.append("&code_challenge_method=S256&code_challenge=").append(codeChallenge);
        }

        if (oauthConfig.isFormPost()) {
            authorizationUrl.append("&response_mode=form_post");
        }

        return authorizationUrl.toString();
    }

    private void printRequest(String msg, RequestEntity<?> req) {
        Map<String, Object> message = new HashMap<>();
        message.put("method", req.getMethod().toString());
        message.put("url", req.getUrl().toString());
        message.put("headers", req.getHeaders());
        if (req.hasBody()) {
            message.put("body", req.getBody());
        }
        logger.debug("ReqeustType=\"" + msg + "\" RequestInfo=" + writeJsonString(req, false));
        return;
    }

    private TokenResponse requestToken(String authorizationCode) {
        StringBuilder tokenRequestUrl = new StringBuilder();
        tokenRequestUrl.append(clientConfig.getTokenEndpoint());

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        headers.add("Authorization",
                "Basic " + OauthUtil.encodeToBasicClientCredential(clientConfig.getClientId(), clientConfig.getClientSecret()));

        MultiValueMap<String, String> params = new LinkedMultiValueMap<String, String>();
        params.add("code", authorizationCode);
        params.add("grant_type", "authorization_code");
        params.add("redirect_uri", clientConfig.getClientappUrl() + "/gettoken");

        if (oauthConfig.isPkce()) {
            params.add("code_verifier", (String) session.getAttribute("codeVerifier"));
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

    private String callApi(String url, String accessToken) {
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

    @RequestMapping("/")
    public String index(Model model, @ModelAttribute("tokenData") TokenResponse sessionData) {
        String scope = (String) session.getAttribute("scope");
        if (scope == null) {
            model.addAttribute("scope", clientConfig.getScope());
        } else {
            model.addAttribute("scope", scope);
        }
        String accessTokenString = (String) session.getAttribute("accessToken");
        if (accessTokenString != null) {
            model.addAttribute("accessTokenString", accessTokenString.substring(0, 20) + "...");
            AccessToken accessToken = OauthUtil.readJsonContent(OauthUtil.decodeFromBase64Url(accessTokenString),
                    AccessToken.class);
            Date exp = new Date(accessToken.getExp() * 1000);
            model.addAttribute("accessTokenExp", exp.toString());
            model.addAttribute("accessTokenScope", accessToken.getScope());
        }
        String refreshTokenString = (String) session.getAttribute("refreshToken");
        if (refreshTokenString != null) {
            model.addAttribute("refreshTokenString", refreshTokenString.substring(0, 20) + "...");
            RefreshToken refreshToken = OauthUtil.readJsonContent(OauthUtil.decodeFromBase64Url(refreshTokenString),
                    RefreshToken.class);
            Date exp = new Date(refreshToken.getExp() * 1000);
            model.addAttribute("refreshTokenExp", exp.toString());
        }

        return "index";
    }

    @RequestMapping(value = "/auth", method = RequestMethod.POST)
    public String auth(@RequestParam("scope") String scope) {
        session.setAttribute("scope", scope);
        String authUrl = getAuthorizationUrl(scope);
        logger.debug("Type=\"Authorization Request\" Status=\"302\" Location=\"" + authUrl + "\"");
        return String.format("redirect:%s", authUrl);
    }

    @RequestMapping(value = "/gettoken", method = RequestMethod.GET)
    public String getToken(@RequestParam(name = "code", required = false) String code,
            @RequestParam(name = "error", required = false) String error,
            @RequestParam(name = "state", required = false) String state, Model model,
            @ModelAttribute("tokenData") TokenResponse sessionData) {

        if (oauthConfig.isFormPost()) {
            return "gettoken";
        }

        if (error == null) {
            return processAuthorizationCodeGrant(code, state, model);
        } else {

            return "gettokenerr";
        }
    }

    @RequestMapping(value = "/gettoken", method = RequestMethod.POST)
    public String getTokenFormPost(@RequestParam("code") String code,
            @RequestParam(name = "state", required = false) String state, Model model,
            @ModelAttribute("tokenData") TokenResponse sessionData) {

        if (!oauthConfig.isFormPost()) {
            return "gettoken";
        }

        return processAuthorizationCodeGrant(code, state, model);
    }

    private String processAuthorizationCodeGrant(String code, String state, Model model) {
        // check state before token request
        if (oauthConfig.isState()) {
            if (state == null || !state.equals(session.getAttribute("state"))) {
                // state check failure. Write error handling here.
                logger.error("state check NG");
                return "gettoken";
            } else {
                logger.debug("state check OK");
                session.setAttribute("state", "");
            }
        }

        TokenResponse token = requestToken(code);
        if (token == null) {
            return "gettoken";
        }

        // check nonce after ID token is obtained
        if (oauthConfig.isNonce() && token.getIdToken() != null) {
            IdToken idToken = OauthUtil.readJsonContent(OauthUtil.decodeFromBase64Url(token.getIdToken()), IdToken.class);
            if (idToken.getNonce() == null || !idToken.getNonce().equals(session.getAttribute("nonce"))) {
                // nonce check failure. Write error handling here.
                logger.error("nonce check NG\n");
                return "gettoken";
            } else {
                logger.debug("nonce check OK\n");
                session.setAttribute("nonce", "");
            }
        }

        session.setAttribute("accessToken", token.getAccessToken());
        session.setAttribute("refreshToken", token.getRefreshToken());
        session.setAttribute("IdToken", token.getIdToken());

        model.addAttribute("accessTokenString", token.getAccessToken());
        model.addAttribute("refreshTokenString", token.getRefreshToken());
        model.addAttribute("IdTokenString", token.getIdToken());

        model.addAttribute("decodedAccessTokenString", decodeJwtToken(token.getAccessToken()));
        model.addAttribute("decodedRefreshTokenString", decodeJwtToken(token.getRefreshToken()));
        model.addAttribute("decodedIDTokenString", decodeJwtToken(token.getIdToken()));
        return "gettoken";
    }

    private String decodeJwtToken(String token) {
        if (token == null) {
            return "";
        }
        Object obj = OauthUtil.readJsonContent(OauthUtil.decodeFromBase64Url(token), Object.class);
        return OauthUtil.writeJsonString(obj);
    }

    private void printResponse(String responseType, ResponseEntity<?> resp) {
        Map<String, Object> message = new HashMap<>();
        message.put("status", resp.getStatusCode().toString());
        message.put("headers", resp.getHeaders());
        message.put("body", resp.getBody());
        logger.debug("ResponseType=\"" + responseType + "\" ResponseInfo=" + writeJsonString(message, false));
        return;
    }

    private void printClientError(String errorType, HttpClientErrorException e) {
        Map<String, Object> message = new HashMap<>();
        message.put("status", e.getStatusCode().toString());
        message.put("headers", e.getResponseHeaders());
        message.put("body", e.getResponseBodyAsString());
        logger.error("ErrorType=\"" + errorType + "\" ResponseInfo=" + writeJsonString(message, false));

    }

    private String writeJsonString(Object obj, boolean indent) {
        ObjectMapper mapper = new ObjectMapper();
        mapper.configure(SerializationFeature.INDENT_OUTPUT, indent);
        try {
            return mapper.writeValueAsString(obj);
        } catch (IOException e) {
            logger.error("unable to deserialize", e);
        }
        return "";
    }

    private TokenResponse refreshToken(String refreshToken) {
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

    private void revokeToken(String refreshToken) {
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

    @RequestMapping(value = "/refresh")
    public String refreshToken(Model model, @ModelAttribute("tokenData") TokenResponse sessionData) {
        String refreshToken = (String) session.getAttribute("refreshToken");
        if (refreshToken == null) {
            return "gettoken";
        }

        TokenResponse token = refreshToken(refreshToken);

        session.setAttribute("accessToken", token.getAccessToken());
        session.setAttribute("refreshToken", token.getRefreshToken());
        session.setAttribute("IdToken", token.getIdToken());
        model.addAttribute("accessTokenString", token.getAccessToken());
        model.addAttribute("refreshTokenString", token.getRefreshToken());
        model.addAttribute("IdTokenString", token.getIdToken());

        model.addAttribute("decodedAccessTokenString", decodeJwtToken(token.getAccessToken()));
        model.addAttribute("decodedRefreshTokenString", decodeJwtToken(token.getRefreshToken()));
        model.addAttribute("decodedIDTokenString", decodeJwtToken(token.getIdToken()));

        return "gettoken";
    }

    @RequestMapping(value = "/revoke")
    public String logout(Model model, @ModelAttribute("tokenData") TokenResponse sessionData) {
        if (session.getAttribute("refreshToken") == null) {
            return "forward:/";
        }

        revokeToken((String) session.getAttribute("refreshToken"));

        // session.setAttribute("accessToken", null);
        // session.setAttribute("refreshToken", null);

        return "forward:/";
    }

    @RequestMapping("/callecho")
    public String callEcho(Model model) {
        String accessToken = (String) session.getAttribute("accessToken");
        String uri = clientConfig.getApiserverUrl() + "/echo";
        String response = callApi(uri, accessToken);
        model.addAttribute("apiResponse", response);
        return "forward:/";
    }

    @RequestMapping("/calldemointrospection")
    public String callReadApi(Model model) {
        String accessToken = (String) session.getAttribute("accessToken");
        String uri = clientConfig.getApiserverUrl() + "/demointrospection";
        String response = callApi(uri, accessToken);
        model.addAttribute("apiResponse", response);
        return "forward:/";
    }

    @RequestMapping("/callreadapi")
    public String callWriteApi(Model model) {
        String accessToken = (String) session.getAttribute("accessToken");
        String uri = clientConfig.getApiserverUrl() + "/readdata";
        String response = callApi(uri, accessToken);
        model.addAttribute("apiResponse", response);
        return "forward:/";
    }
}