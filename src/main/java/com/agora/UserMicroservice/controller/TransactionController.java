package com.agora.UserMicroservice.controller;

import com.agora.UserMicroservice.entity.Transaction;
import com.agora.UserMicroservice.payload.request.TransactionRequest;
import com.agora.UserMicroservice.repository.TransactionRepository;
import com.agora.UserMicroservice.security.jwt.JwtUtils;
import com.agora.UserMicroservice.security.services.UserDetailsImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;
import com.agora.UserMicroservice.service.TransactionService;

import javax.validation.Valid;
import java.util.Date;
import java.util.List;
import java.util.Optional;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/transaction")
public class TransactionController {

    @Autowired
    private TransactionService transactionService;

    @Autowired
    private TransactionRepository transactionRepository;
    @Autowired
    JwtUtils jwtUtils;

    @GetMapping("/get_history")
    public ResponseEntity<Optional<List<Transaction>>> getTransaction(@Valid @RequestHeader(value = "Authorization") String token){
        token = token.split(" ")[1].trim();
        if(jwtUtils.validateJwtToken(token)){
            UserDetailsImpl userDetails = (UserDetailsImpl) SecurityContextHolder.getContext().getAuthentication().getPrincipal();

            return ResponseEntity.ok(transactionService.getAllTransactions(userDetails.getEmail()));
        }
        return ResponseEntity.badRequest().build();

    }

    @PostMapping("/save_transaction")
    public ResponseEntity<?> saveTransaction(@Valid @RequestHeader(value = "Authorization") String token,@RequestBody TransactionRequest transactionRequest){
        token = token.split(" ")[1].trim();
        if(jwtUtils.validateJwtToken(token)){
            UserDetailsImpl userDetails = (UserDetailsImpl) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
            Transaction transaction =new Transaction();
            transaction.setSender("ADMIN");
            transaction.setDatasetName(transactionRequest.getDatasetName());
            transaction.setTransactionDate((new Date((new Date()).getTime())).toString());
            transaction.setPrice(1.5F);
            transaction.setRecepient(userDetails.getEmail());
            transactionRepository.save(transaction);
            return new ResponseEntity<>(HttpStatus.CREATED);

        }
        return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
    }

}
