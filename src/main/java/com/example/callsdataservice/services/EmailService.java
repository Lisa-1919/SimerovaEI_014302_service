package com.example.callsdataservice.services;

import com.example.callsdataservice.payload.request.SendEmailRequest;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Service
public class EmailService {

    public boolean sendEmail(SendEmailRequest sendEmailRequest, String emailFrom) throws IOException {

        OkHttpClient client = new OkHttpClient();

        MediaType mediaType = MediaType.parse("application/json");
        okhttp3.RequestBody body = okhttp3.RequestBody.create(mediaType,
                "{\n" +
                        "    \"sendto\": " + sendEmailRequest.getEmailTo()+",\n" +
                        "    \"name\": \"Custom Name Here\",\n" +
                        "    \"replyTo\": "+emailFrom+",\n" +
                        "    \"ishtml\": \"false\",\n" +
                        "    \"title\": \"Put Your Title Here\",\n" +
                        "    \"body\": " + sendEmailRequest.getMessage() +"\n" +
                        "}");
        Request request = new Request.Builder()
                .url("https://mail-sender-api1.p.rapidapi.com/")
                .post(body)
                .addHeader("content-type", "application/json")
                .addHeader("X-RapidAPI-Key", "459c909060msh259d284d0105b54p151393jsnbb0570bf2901")
                .addHeader("X-RapidAPI-Host", "mail-sender-api1.p.rapidapi.com")
                .build();
        Response response = client.newCall(request).execute();
        return response.isSuccessful();
    }
    public boolean isValidEmail(String email) {
        String regex = "^(.+)@(.+)$";
        Pattern pattern = Pattern.compile(regex);
        Matcher matcher = pattern.matcher(email);
        return matcher.matches();
    }
}
