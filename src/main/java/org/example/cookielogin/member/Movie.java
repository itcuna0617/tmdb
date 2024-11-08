package org.example.cookielogin.member;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;
import java.util.Date;

@Entity
@Getter
@Setter
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class Movie {
    @Id
    private Long movieId;
    private String title;
    @Lob
    private String overview;
    private Date releaseDate;
    private Double voteAverage;
    private int voteCount;
    private String posterPath;
    private String backdropPath;
    @Lob
    private String trailerPath;
}
