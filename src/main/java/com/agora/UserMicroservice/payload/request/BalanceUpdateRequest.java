package com.agora.UserMicroservice.payload.request;

import javax.validation.constraints.NotBlank;

public class BalanceUpdateRequest {

    @NotBlank
    private Float balance;

    public Float getBalance() { return balance; }

    public void setBalance(Float balance){ this.balance = balance; }
}
