package sample.clientapp;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;

import sample.clientapp.config.ClientAppConfiguration;
import sample.clientapp.config.OauthConfiguration;
import sample.clientapp.jwt.AccessToken;
import sample.clientapp.jwt.RefreshToken;
import sample.clientapp.service.ClientAppService;

@Controller
public class ClientAppController {

    private static final Logger logger = LoggerFactory.getLogger(ClientAppController.class);

    @Autowired
    ClientAppConfiguration clientConfig;

    @Autowired
    OauthConfiguration oauthConfig;

    @Autowired
    ClientAppService service;

    @Autowired
    ClientSession clientSession;

    @RequestMapping("/")
    public String index() {
        return "index";
    }

    @RequestMapping(value = "/auth", method = RequestMethod.POST)
    public String auth(@RequestParam("scope") String scope) {
        clientSession.setScope(scope);
        String authUrl = service.getAuthorizationUrl(scope);
        logger.debug("Type=\"Authorization Request\" Status=\"302\" Location=\"" + authUrl + "\"");
        return String.format("redirect:%s", authUrl);
    }

    @RequestMapping(value = "/gettoken", method = RequestMethod.GET)
    public String getToken(@RequestParam(name = "code", required = false) String code,
            @RequestParam(name = "error", required = false) String error,
            @RequestParam(name = "state", required = false) String state) {

        if (oauthConfig.isFormPost()) {
            return "gettoken";
        }

        if (error == null) {
            return service.processAuthorizationCodeGrant(code, state);
        } else {

            return "gettokenerr";
        }
    }

    @RequestMapping(value = "/gettoken", method = RequestMethod.POST)
    public String getTokenFormPost(@RequestParam("code") String code,
            @RequestParam(name = "state", required = false) String state) {

        if (!oauthConfig.isFormPost()) {
            return "gettoken";
        }

        return service.processAuthorizationCodeGrant(code, state);
    }

    @RequestMapping(value = "/refresh")
    public String refreshToken(Model model, @ModelAttribute("tokenData") TokenResponse sessionData) {
        RefreshToken token = clientSession.getRefreshToken();
        if (token == null) {
            return "gettoken";
        }

        TokenResponse response = service.refreshToken(token.getTokenString());
        clientSession.setTokensFromTokenResponse(response);
        return "gettoken";
    }

    @RequestMapping(value = "/revoke")
    public String logout(Model model, @ModelAttribute("tokenData") TokenResponse sessionData) {
        RefreshToken refreshToken = clientSession.getRefreshToken();
        if (refreshToken == null) {
            return "forward:/";
        }

        service.revokeToken(refreshToken.getTokenString());

        // session.setAttribute("accessToken", null);
        // session.setAttribute("refreshToken", null);

        return "forward:/";
    }

    @RequestMapping("/callecho")
    public String callEcho(Model model) {
        AccessToken accessToken = clientSession.getAccessToken();
        String uri = clientConfig.getApiserverUrl() + "/echo";
        String response = service.callApi(uri, accessToken.getTokenString());
        model.addAttribute("apiResponse", response);
        return "forward:/";
    }

    @RequestMapping("/calldemointrospection")
    public String callReadApi(Model model) {
        AccessToken accessToken = clientSession.getAccessToken();
        String uri = clientConfig.getApiserverUrl() + "/demointrospection";
        String response = service.callApi(uri, accessToken.getTokenString());
        model.addAttribute("apiResponse", response);
        return "forward:/";
    }

    @RequestMapping("/callreadapi")
    public String callWriteApi(Model model) {
        AccessToken accessToken = clientSession.getAccessToken();
        String uri = clientConfig.getApiserverUrl() + "/readdata";
        String response = service.callApi(uri, accessToken.getTokenString());
        model.addAttribute("apiResponse", response);
        return "forward:/";
    }
}