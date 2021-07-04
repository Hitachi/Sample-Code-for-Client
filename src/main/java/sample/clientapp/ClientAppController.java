package sample.clientapp;

import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URLEncoder;
import java.util.UUID;
import java.util.Date;

import javax.servlet.http.HttpSession;

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

    @Autowired
    HttpSession session;

    @Autowired
    ClientAppConfiguration clientConfig;

    @Autowired
    OauthConfiguration oauthConfig;

    @Autowired
    RestTemplate restTemplate;

    private String getAuthorizationUrl() {
        StringBuilder authorizationUrl = new StringBuilder();
        authorizationUrl.append(clientConfig.getAuthserverUrl()).append(clientConfig.getAuthorizationEndpoint());

        String redirectUrl;
        String scope;
        try {
            redirectUrl = URLEncoder.encode(clientConfig.getClientappUrl() + "/gettoken", "UTF-8");
            scope = clientConfig.getScope();
            if (scope!=null && !scope.isEmpty())
                scope = URLEncoder.encode(scope, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            return "";
        }

        if(scope != null && !scope.isEmpty() ) {
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

    private void printRequest(String msg, RequestEntity req) {

         System.out.println(msg);
         System.out.println(req.getMethod().toString());
         System.out.println(req.getUrl().toString());
         System.out.println(" - Headers:\n"+req.getHeaders().toString());
         if (req.hasBody())
             System.out.println(" - Body:\n"+req.getBody().toString()+"\n");
         else
             System.out.println("\n");
        return;
    }

    private TokenResponse requestToken(String authorizationCode) {
        StringBuilder tokenRequestUrl = new StringBuilder();
        tokenRequestUrl.append(clientConfig.getAuthserverUrl()).append(clientConfig.getTokenEndpoint());

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        headers.add("Authorization", "Basic " + OauthUtil.encodeToBasicClientCredential(clientConfig.getClientId(), clientConfig.getClientSecret()));

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
            printRequest("* Token Request:", req);

            ResponseEntity<TokenResponse> res = restTemplate.exchange(req, TokenResponse.class);
            token = res.getBody();
            printTokenResponse(res,token);

        } catch (HttpClientErrorException e) {
            System.out.println("!! response code=" + e.getStatusCode()+"\n");
            System.out.println(e.getResponseBodyAsString()+"\n");
        }

        return token;
    }

    private String callApi(String url, String accessToken) {
        HttpHeaders headers = new HttpHeaders();
        if (accessToken != null) {
            headers.setBearerAuth(accessToken);
        }

        RequestEntity<?> req = new RequestEntity<>(headers, HttpMethod.GET, URI.create(url));
//           System.out.println("Called API:"+ req.toString()+"\n");
           printRequest("Called API:",req);
        String response = null;
        try {
            ResponseEntity<String> res = restTemplate.exchange(req, String.class);
            response = res.getBody();
//            System.out.println(response.toString()+"\n");
        } catch (HttpClientErrorException e) {
            System.out.println("!! response code=" + e.getStatusCode()+"\n");
            System.out.println(e.getResponseBodyAsString()+"\n");
            response = e.getStatusCode().toString();
        }

        return response;
    }

    @RequestMapping("/")
    public String index(Model model, @ModelAttribute("tokenData") TokenResponse sessionData) {

        model.addAttribute("authorizationUrl", getAuthorizationUrl());

        String accessTokenString = (String) session.getAttribute("accessToken");
        if (accessTokenString != null) {
            model.addAttribute("accessTokenString", accessTokenString.substring(0, 20) + "...");
            AccessToken accessToken = OauthUtil.readJsonContent(OauthUtil.decodeFromBase64Url(accessTokenString), AccessToken.class);
            Date exp = new Date(accessToken.getExp() * 1000);
            model.addAttribute("accessTokenExp", exp.toString());
            model.addAttribute("accessTokenScope", accessToken.getScope());
        }
        String refreshTokenString = (String) session.getAttribute("refreshToken");
        if (refreshTokenString != null) {
            model.addAttribute("refreshTokenString", refreshTokenString.substring(0, 20) + "...");
            RefreshToken refreshToken = OauthUtil.readJsonContent(OauthUtil.decodeFromBase64Url(refreshTokenString), RefreshToken.class);
            Date exp = new Date(refreshToken.getExp() * 1000);
            model.addAttribute("refreshTokenExp", exp.toString());
        }

        return "index";
    }

    @RequestMapping(value = "/gettoken", method = RequestMethod.GET)
      public String getToken(@RequestParam("code") String code,
        @RequestParam(name = "state", required = false) String state, Model model,
        @ModelAttribute("tokenData") TokenResponse sessionData) {

        if (oauthConfig.isFormPost()) {
            return "gettoken";
        }

        return processAuthorizationCodeGrant(code, state, model);
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
        if (oauthConfig.isState()) {
            if (state == null || !state.equals(session.getAttribute("state"))) {
                return "gettoken";
            } else {
                session.setAttribute("state","");
            }
        }

        TokenResponse token = requestToken(code);
        if (token == null) {
            return "gettoken";
        }

        if (oauthConfig.isNonce()) {
            IdToken idToken = OauthUtil.readJsonContent(OauthUtil.decodeFromBase64Url(token.getIdToken()), IdToken.class);
            if (idToken.getNonce() == null || !idToken.getNonce().equals(session.getAttribute("nonce"))) {
                return "gettoken";
            } else {
                session.setAttribute("nonce","");
            }
        }

        session.setAttribute("accessToken", token.getAccessToken());
        session.setAttribute("refreshToken", token.getRefreshToken());
        session.setAttribute("IdToken", token.getIdToken());

        model.addAttribute("accessTokenString", token.getAccessToken());
        model.addAttribute("refreshTokenString", token.getRefreshToken());
        model.addAttribute("IdTokenString", token.getIdToken());

        return "gettoken";
    }

    private void printTokenResponse(ResponseEntity res, TokenResponse token) {
        System.out.println("* Response:");
        System.out.println("-Status:"+res.getStatusCode().toString());
        System.out.println("-Headers:"+res.getHeaders().toString());
        System.out.println("-Body:");
        System.out.println("access_token,"+ "\""+ token.getAccessToken() +"\"");
        System.out.println("expires_in,"+ token.getExpiresIn());
        System.out.println("refresh_token," +"\""+ token.getRefreshToken()+"\"");
        System.out.println("refresh_expires_in,"+ token.getRefreshExpiresIn());
        System.out.println("id_token," +"\""+ token.getIdToken()+"\"");
        System.out.println("token_type,"+ token.getTokenType());
        System.out.println("not_before_policy,"+ "\""+token.getNotBeforePolicy()+"\"");
        System.out.println("session_state,"+ "\""+token.getSessionState()+"\"");
        System.out.println("scope,"+ "\""+token.getScope()+"\"");
        System.out.flush();
    }

    private TokenResponse refreshToken(String refreshToken) {
        StringBuilder tokenRequestUrl = new StringBuilder();
        tokenRequestUrl.append(clientConfig.getAuthserverUrl()).append(clientConfig.getTokenEndpoint());

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        headers.add("Authorization", "Basic " + OauthUtil.encodeToBasicClientCredential(clientConfig.getClientId(), clientConfig.getClientSecret()));

        MultiValueMap<String, String> params = new LinkedMultiValueMap<String, String>();
        params.add("grant_type", "refresh_token");
        params.add("refresh_token", refreshToken);

        RequestEntity<?> req = new RequestEntity<>(params, headers, HttpMethod.POST, URI.create(tokenRequestUrl.toString()));
        TokenResponse token = null;
        printRequest("*Refresh Request",req);

        try {
            ResponseEntity<TokenResponse> res = restTemplate.exchange(req, TokenResponse.class);
            token = res.getBody();
            printTokenResponse(res,token);
        } catch (HttpClientErrorException e) {
            System.out.println("!! response code=" + e.getStatusCode()+"\n");
            System.out.println(e.getResponseBodyAsString()+"\n");
        }

        return token;
    }

    private void revokeToken(String refreshToken) {
        StringBuilder revokeUrl = new StringBuilder();
        revokeUrl.append(clientConfig.getAuthserverUrl()).append(clientConfig.getRevokeEndpoint());

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        headers.add("Authorization", "Basic " + OauthUtil.encodeToBasicClientCredential(clientConfig.getClientId(), clientConfig.getClientSecret()));

        MultiValueMap<String, String> params = new LinkedMultiValueMap<String, String>();
        params.add("token", refreshToken);
        params.add("token_type_hint", "refresh_token");

        RequestEntity<?> req = new RequestEntity<>(params, headers, HttpMethod.POST, URI.create(revokeUrl.toString()));

        printRequest("*Revoke Request:",req);

        try {
          restTemplate.exchange(req, Object.class);
        } catch (HttpClientErrorException e) {
            System.out.println("!! response code=" + e.getStatusCode()+"\n");
            System.out.println(e.getResponseBodyAsString()+"\n");
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

        return "gettoken";
    }

    @RequestMapping(value = "/revoke")
    public String logout(Model model, @ModelAttribute("tokenData") TokenResponse sessionData) {
        if (session.getAttribute("refreshToken") == null) {
            return "logout";
        }

        revokeToken((String) session.getAttribute("refreshToken"));

        session.setAttribute("accessToken", null);
        session.setAttribute("refreshToken", null);

        return "logout";
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