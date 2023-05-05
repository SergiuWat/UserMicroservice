package com.agora.UserMicroservice.payload.request;

public class TransactionRequest {

    private String  datasetName;

    private Float datasetPrice;

    public String getDatasetName() {
        return datasetName;
    }

    public Float getDatasetPrice() { return datasetPrice; }

    public void setDatasetPrice(Float datasetPrice) { this.datasetPrice = datasetPrice; }

    public void setDatasetName(String datasetName) {
        this.datasetName = datasetName;
    }


}
