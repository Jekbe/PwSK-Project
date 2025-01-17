package lastPosts;

import java.util.List;

public record LastPostsResponse(int status, String message, List<String> posts) {
}
