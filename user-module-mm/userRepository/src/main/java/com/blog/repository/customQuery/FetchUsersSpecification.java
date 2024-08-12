package com.blog.repository.customQuery;

import com.blog.repository.entity.User;
import jakarta.persistence.criteria.Predicate;
import org.springframework.data.jpa.domain.Specification;

import java.util.ArrayList;
import java.util.List;

public class FetchUsersSpecification {

    public static Specification<User> getUsersWithDynamicQuery(List<String> searchColumns, String keyword) {
        return (root, query, criteriaBuilder) -> {
            List<Predicate> predicates = new ArrayList<>();

            for (String column : searchColumns) {
                switch (column.toLowerCase()) {
                    case "username":
                        predicates.add(criteriaBuilder.like(root.get("username"), "%" + keyword + "%"));
                        break;
                    case "name":
                        predicates.add(criteriaBuilder.like(root.get("name"), "%" + keyword + "%"));
                        break;
                    case "address":
                        predicates.add(criteriaBuilder.like(root.get("address"), "%" + keyword + "%"));
                        break;
                    case "empcode":
                        predicates.add(criteriaBuilder.like(root.get("empCode"), "%" + keyword + "%"));
                        break;
                    case "backupemail":
                        predicates.add(criteriaBuilder.like(root.get("backup_email"), "%" + keyword + "%"));
                        break;
                    case "email":
                        predicates.add(criteriaBuilder.like(root.get("email"), "%" + keyword + "%"));
                        break;
                    case "mobile":
                        predicates.add(criteriaBuilder.like(root.get("mobile_number"), "%" + keyword + "%"));
                        break;
                }
            }
            return criteriaBuilder.or(predicates.toArray(new Predicate[0]));
        };
    }
}