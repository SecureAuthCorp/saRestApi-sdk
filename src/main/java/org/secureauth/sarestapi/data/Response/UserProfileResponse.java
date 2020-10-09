package org.secureauth.sarestapi.data.Response;

import com.fasterxml.jackson.annotation.JsonInclude;
import org.secureauth.sarestapi.data.Response.BaseResponse;
import org.secureauth.sarestapi.data.UserProfile.*;
import org.secureauth.sarestapi.util.JSONUtil;

import javax.xml.bind.annotation.XmlRootElement;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Created by rrowcliffe on 5/1/16.
 */
@XmlRootElement
@JsonInclude(JsonInclude.Include.NON_NULL)
public class UserProfileResponse extends BaseResponse{
    private String userId;
    private Map<String,UserProfileProperty> properties = new HashMap<>();
    private Map<String,UserProfileKB> knowledgeBase = new LinkedHashMap<>();
    private List<String> groups = new ArrayList<>();
    private List<UserProfileAccessHistory> accessHistories = new ArrayList<>();

    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }

    public Map<String, UserProfileProperty> getProperties() {
        return properties;
    }

    public void setProperties(HashMap<String, UserProfileProperty> properties) {
        this.properties = properties;
    }

    public Map<String, UserProfileKB> getKnowledgeBase() {
        return knowledgeBase;
    }

    public void setKnowledgeBase(HashMap<String, UserProfileKB> knowledgeBase) {
        this.knowledgeBase = knowledgeBase;
    }

    public List<String> getGroups() {
        return groups;
    }

    public void setGroups(List<String> groups) {
        this.groups = groups;
    }

    public List<UserProfileAccessHistory> getAccessHistories() {
        return accessHistories;
    }

    public void setAccessHistories(List<UserProfileAccessHistory> accessHistories) {
        this.accessHistories = accessHistories;
    }

    @Override
    public String toString(){
        return JSONUtil.convertObjectToJSON(this);
    }
}
