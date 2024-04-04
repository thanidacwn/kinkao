package ku.kinkao.service;


import ku.kinkao.dto.ReviewRequest;
import ku.kinkao.entity.Restaurant;
import ku.kinkao.entity.Review;
import ku.kinkao.repository.RestaurantRepository;
import ku.kinkao.repository.ReviewRepository;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;


import java.time.Instant;


@Service
public class ReviewService {


    @Autowired
    private ReviewRepository reviewRepository;


    @Autowired
    private RestaurantRepository restaurantRepository;


    @Autowired
    private ModelMapper modelMapper;


    public void createReview(ReviewRequest reviewRequest) {
        Review review = modelMapper.map(reviewRequest, Review.class);
        review.setCreatedAt(Instant.now());


        Restaurant restaurant =
                restaurantRepository.findById(reviewRequest.getRestaurantId()).get();


        review.setRestaurant(restaurant);


        reviewRepository.save(review);
    }
}
