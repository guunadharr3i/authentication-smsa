package com.example.authentication.Repo;

import com.example.authentication.Entity.SmsaUser;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

@Repository
public interface UserRepository extends JpaRepository<SmsaUser, Long> {

    @Query("SELECT u FROM SmsaUser u WHERE u.loginId = :loginId")
    SmsaUser findByLoginId(@Param("loginId") String loginId);
}
