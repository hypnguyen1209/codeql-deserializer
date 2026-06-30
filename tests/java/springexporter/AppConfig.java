package springexporter;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class AppConfig {

    // Vulnerable: bean is a Spring remoting exporter that deserializes input.
    @Bean(name = "myExporter")
    public MyExporter myExporter() {
        return new MyExporter();
    }

    // Safe: bean is a plain service, not a remoting exporter.
    @Bean
    public PlainService plainService() {
        return new PlainService();
    }
}
