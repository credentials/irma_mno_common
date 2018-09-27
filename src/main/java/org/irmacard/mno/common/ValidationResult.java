package org.irmacard.mno.common;

public class ValidationResult {
    public enum Result {VALID,INVALID}
    private Result result;
    private String message;

    public ValidationResult(Result result, String message) {
        this.result = result;
        this.message = message;
    }

    public ValidationResult(Result result){
        this.result = result;
    }

    public boolean isValid(){
        return result.equals(Result.VALID);
    }

    public Result getResult() {
        return result;
    }

    public void setResult(Result result) {
        this.result = result;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }
}
