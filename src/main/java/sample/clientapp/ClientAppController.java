package sample.clientapp;

import java.util.Date;

import javax.servlet.http.HttpSession;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;

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
    ClientAppService service;

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
        String authUrl = service.getAuthorizationUrl(scope);
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

        TokenResponse token = service.requestToken(code);
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

    @RequestMapping(value = "/refresh")
    public String refreshToken(Model model, @ModelAttribute("tokenData") TokenResponse sessionData) {
        String refreshToken = (String) session.getAttribute("refreshToken");
        if (refreshToken == null) {
            return "gettoken";
        }

        TokenResponse token = service.refreshToken(refreshToken);

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

        service.revokeToken((String) session.getAttribute("refreshToken"));

        // session.setAttribute("accessToken", null);
        // session.setAttribute("refreshToken", null);

        return "forward:/";
    }

    @RequestMapping("/callecho")
    public String callEcho(Model model) {
        String accessToken = (String) session.getAttribute("accessToken");
        String uri = clientConfig.getApiserverUrl() + "/echo";
        String response = service.callApi(uri, accessToken);
        model.addAttribute("apiResponse", response);
        return "forward:/";
    }

    @RequestMapping("/calldemointrospection")
    public String callReadApi(Model model) {
        String accessToken = (String) session.getAttribute("accessToken");
        String uri = clientConfig.getApiserverUrl() + "/demointrospection";
        String response = service.callApi(uri, accessToken);
        model.addAttribute("apiResponse", response);
        return "forward:/";
    }

    @RequestMapping("/callreadapi")
    public String callWriteApi(Model model) {
        String accessToken = (String) session.getAttribute("accessToken");
        String uri = clientConfig.getApiserverUrl() + "/readdata";
        String response = service.callApi(uri, accessToken);
        model.addAttribute("apiResponse", response);
        return "forward:/";
    }
}