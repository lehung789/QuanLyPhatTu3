package com.example.quanlyphattudemo.dto.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class ResponseMessage {
    private String status;
    private String message;
    // bao het dt truyen xuong list, doi tg ...
    private Object data;

    public ResponseMessage(String message) {
        this.message = message;
    }
}
