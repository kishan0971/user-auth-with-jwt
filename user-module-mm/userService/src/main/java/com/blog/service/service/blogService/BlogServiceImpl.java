package com.blog.service.service.blogService;

import com.blog.repository.DTO.BlogCreationFeignClient;
import com.blog.repository.DTO.BlogCreationRequest;
import com.blog.repository.entity.User;
import com.blog.repository.repository.UserRepository;
import com.blog.service.exceptions.DepartmentNotFoundException;
import com.blog.service.exceptions.TeamNotFoundException;
import com.blog.service.externalServices.ExternalBlogService;
import com.blog.service.helper.BlogHelper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;

@Service
public class BlogServiceImpl implements BlogService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private BlogHelper blogHelper;

    @Autowired
    private BlogCreationFeignClient blogCreationClient;

    @Autowired
    private ExternalBlogService externalBlogService;

    @Override
    public Map<String, Object> createBlog(String creator, BlogCreationRequest blogCreationRequest) throws IOException {
        try {
            blogHelper.checkExistenceOfTeam(blogCreationRequest.getTeam_visibility());
            blogHelper.checkExistenceOfDepartment(blogCreationRequest.getDepartment_visibility());
            List<String> base64Files = new ArrayList<>();
            for (MultipartFile file : blogCreationRequest.getFiles()) {
                byte[] fileBytes = file.getBytes();
                String base64Encoded = Base64.getEncoder().encodeToString(fileBytes);
                base64Files.add(base64Encoded);
            }
            User sender = userRepository.findByUserName(creator);
            blogCreationClient.setUserId(sender.getId());
            blogCreationClient.setUserName(sender.getUserName());
            blogCreationClient.setTitle(blogCreationRequest.getTitle());
            blogCreationClient.setContent(blogCreationRequest.getContent());
            blogCreationClient.setTeam_visibility(blogCreationRequest.getTeam_visibility());
            blogCreationClient.setDepartment_visibility(blogCreationRequest.getDepartment_visibility());
            blogCreationClient.setFilesBase64Encoded(base64Files);
            Map<String, Object> response = externalBlogService.postBlog(blogCreationClient);
            return null;
        } catch (TeamNotFoundException | DepartmentNotFoundException e) {
            throw e;
        } catch (Exception e) {
            throw new IOException("Error creating blog: " + e.getMessage());
        }
    }
}