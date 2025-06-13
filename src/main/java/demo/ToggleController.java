package main.java.demo;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ToggleController {
    private boolean state = true;

    @GetMapping("/toggle")
    public String toggleMessage() {
        state = !state;
        return state ? "Hello World" : "Loading...";
    }
}