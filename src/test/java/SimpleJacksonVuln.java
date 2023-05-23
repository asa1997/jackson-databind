import com.fasterxml.jackson.databind.BaseMapTest;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectMapper.DefaultTyping;
import com.fasterxml.jackson.databind.exc.InvalidDefinitionException;
import org.apache.xalan.lib.sql.JNDIConnectionPool;
import org.junit.Test;
import com.fasterxml.jackson.annotation.JsonTypeInfo;

public class SimpleJacksonVuln extends BaseMapTest{
    @Test
    public void testVulnerability() throws Exception {
    	String clsname = "org.docx4j.org.apache.xalan.lib.sql.JNDIConnectionPool";
    	String payload = aposToQuotes(String.format("{'@class':'%s','jndiPath':'ldap://localhost:81'}",JNDIConnectionPool.class.getName()));
    	ObjectMapper mapper = new ObjectMapper();
        try {
            
        	mapper.enableDefaultTyping(DefaultTyping.NON_FINAL, JsonTypeInfo.As.PROPERTY);
        	JNDIConnectionPool obj = mapper.readValue(payload, JNDIConnectionPool.class);
            System.out.println(obj);
        } catch (JsonMappingException e) {
            // If we catch an exception, the vulnerability was triggered and the test passed
        	 _verifySecurityException(e, clsname);
            System.out.println("Vulnerability triggered "+e);
        }
    }
    protected void _verifySecurityException(Throwable t, String clsName) throws Exception
    {
        _verifyException(t, InvalidDefinitionException.class,
            "Illegal type",
            "to deserialize",
            "prevented for security reasons");
        verifyException(t, clsName);
    }

    protected void _verifyException(Throwable t, Class<?> expExcType,
            String... patterns) throws Exception
    {
        Class<?> actExc = t.getClass();
        if (!expExcType.isAssignableFrom(actExc)) {
            fail("Expected Exception of type '"+expExcType.getName()+"', got '"
                    +actExc.getName()+"', message: "+t.getMessage());
        }
        for (String pattern : patterns) {
            verifyException(t, pattern);
        }
    }
}