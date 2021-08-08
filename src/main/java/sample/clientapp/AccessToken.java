package sample.clientapp;

import java.util.Arrays;
import java.util.List;

import com.fasterxml.jackson.databind.PropertyNamingStrategy;
import com.fasterxml.jackson.databind.annotation.JsonNaming;

@JsonNaming(PropertyNamingStrategy.SnakeCaseStrategy.class)
public class AccessToken {
    private long exp;
    private String scope;

    public long getExp() {
        return exp;
    }

    public void setExp(long value) {
        exp = value;
    }

    public String getScope() {
        return scope;
    }

    public void setScope(String value) {
        scope = value;
    }

    public List<String> getScopeList() {
        return Arrays.asList(scope.split(" "));
    }
}
