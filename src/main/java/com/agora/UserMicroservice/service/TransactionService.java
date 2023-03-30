package com.agora.UserMicroservice.service;

import com.agora.UserMicroservice.entity.Transaction;
import com.agora.UserMicroservice.repository.TransactionRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
public class TransactionService {

    @Autowired
    private TransactionRepository transactionRepository;

    public Optional<List<Transaction>> getAllTransactions(String email){
        return transactionRepository.findByRecepient(email);

    }

}
