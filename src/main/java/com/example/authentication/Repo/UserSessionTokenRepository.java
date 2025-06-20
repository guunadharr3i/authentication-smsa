/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package com.example.authentication.Repo;

import com.example.authentication.Entity.UserSessionToken;
import org.springframework.data.jpa.repository.JpaRepository;

/**
 *
 * @author abcom
 */
public interface UserSessionTokenRepository extends JpaRepository<UserSessionToken,Long> {

    UserSessionToken findByUserIdAndDeviceHashAndStatusTrue(String userId, String deviceHash);
    
    UserSessionToken findByTokenAndDeviceHash(String token, String deviceHash);


    UserSessionToken findByUserIdAndTokenAndDeviceHashAndStatusTrue(String userId,String token, String deviceHash);

}
