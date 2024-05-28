package io.security.oauth2resourceserver.controller;

import io.security.oauth2resourceserver.dto.Photo;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class PhotoController {

    @GetMapping("/photos/1")
    public Photo photo1() {
        return Photo.builder()
                .photoId("1")
                .photoTitle("Photo 1 Title")
                .photoDescription("Photo is nice")
                .userId("user1")
                .build();
    }

    @GetMapping("/photos/2")
    public Photo photo2() {
        return Photo.builder()
                .photoId("2")
                .photoTitle("Photo 2 Title")
                .photoDescription("Photo is nice")
                .userId("user2")
                .build();
    }

    @GetMapping("/photos/3")
    public Photo photo3() {
        return Photo.builder()
                .photoId("3")
                .photoTitle("Photo 3 Title")
                .photoDescription("Photo is nice")
                .userId("user3")
                .build();
    }
}
