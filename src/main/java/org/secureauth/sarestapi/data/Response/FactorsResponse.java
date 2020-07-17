package org.secureauth.sarestapi.data.Response;

/**
 * @author rrowcliffe@secureauth.com
 *
 */
import com.fasterxml.jackson.annotation.JsonInclude;
import org.secureauth.sarestapi.data.Factors;
import org.secureauth.sarestapi.util.JSONUtil;


import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlSeeAlso;
import java.util.ArrayList;

@XmlRootElement
@XmlSeeAlso(Factors.class)
@JsonInclude(JsonInclude.Include.NON_NULL)
public class FactorsResponse extends BaseResponse{

    private ArrayList<Factors> factors = new ArrayList<Factors>();

    public ArrayList<Factors> getFactors() {
        return factors;
    }

    public void setFactors(ArrayList<Factors> factors) {
        this.factors = factors;
    }

    @Override
    public FactorsResponse notFoundResponse(String message, String user_id) {
        super.notFoundResponse(message, user_id);
        return this;
    }

    @Override
    public String toString(){
        return JSONUtil.convertObjectToJSON(this);
    }
}
