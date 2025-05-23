package org.example.expert.domain.todo.repository;

import org.example.expert.domain.todo.entity.Todo;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.LocalDateTime;
import java.util.Optional;

public interface TodoRepository extends JpaRepository<Todo, Long>, TodoRepositoryQuerydsl {

    @Query("SELECT t FROM Todo t LEFT JOIN FETCH t.user u where t.weather = :weather and t.modifiedAt between :startAt and :closedAt ORDER BY t.modifiedAt DESC")
    Page<Todo> findAllByOrderByModifiedAtDesc(Pageable pageable, @Param("weather") String weather, @Param("startAt") LocalDateTime startAt, @Param("closedAt") LocalDateTime closedAt);

}
