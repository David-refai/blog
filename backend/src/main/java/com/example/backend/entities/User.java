package com.example.backend.entities;


import com.example.backend.dto.UserDto;
import com.example.backend.mapper.UserDTOMapper;
import com.fasterxml.jackson.annotation.*;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.proxy.HibernateProxy;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.time.LocalDateTime;
import java.util.*;

//import jakarta.validation.constraints.Email;
//import org.hibernate.annotations.GenericGenerator;
//import org.hibernate.validator.constraints.Range;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@ToString(exclude = {"likes", "posts", "comments"})
@Builder
@Entity
@Table(name = "user")
@JsonIgnoreProperties({"hibernateLazyInitializer",
        "handler"})
public class User implements UserDetails {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;


    @Column(name = "name")
    private String name;

    @Column(name = "email", unique = true)
    private String email;


    @Column(name = "password")
    private String password;

    @Column(name = "image", columnDefinition = "TEXT")
    private String image;

    @Column(name = "date" , columnDefinition = "DATE")
    private @LastModifiedDate LocalDateTime createdAt;

    // One person can have multiple roles
    @JsonManagedReference
    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL , fetch = FetchType.EAGER)
    private List<Roles> roles;

    // One person can have multiple posts

    @JsonIgnore
    @OneToMany(mappedBy = "author", cascade = CascadeType.ALL, fetch = FetchType.LAZY)
    private List<Posts> posts;

    // One person can write multiple comments
    @ManyToOne(fetch = FetchType.LAZY, cascade = {CascadeType.PERSIST, CascadeType.MERGE})
    @JoinColumn(name = "user_id")
    @JsonProperty("user_id")
    private User user;

    // One person can like multiple posts
    @OneToMany(mappedBy = "user")
    private List<Likes> likes;

        @Override
        public Collection<? extends GrantedAuthority> getAuthorities() {
            List<SimpleGrantedAuthority> authorities = new ArrayList<>();
            for (Roles role : roles) {
                authorities.add(new SimpleGrantedAuthority("ROLE_" + role.getName()));
            }
            return authorities;
//            return roles.stream().toList();
        }

        @Override
        public String getUsername() {
            return email;
        }

        @Override
        public boolean isAccountNonExpired() {
            return true;
        }

        @Override
        public boolean isAccountNonLocked() {
            return true;
        }

        @Override
        public boolean isCredentialsNonExpired() {
            return true;
        }

        @Override
        public boolean isEnabled() {
            return true;
        }



    public void addRole(Roles authority) {
        if (roles == null) {
            roles = new ArrayList<>();
        }
        roles.add(authority);
        authority.setUser(this);



    }

    @Override
    public final boolean equals(Object o) {
        if (this == o) return true;
        if (o == null) return false;
        Class<?> oEffectiveClass = o instanceof HibernateProxy ? ((HibernateProxy) o).getHibernateLazyInitializer().getPersistentClass() : o.getClass();
        Class<?> thisEffectiveClass = this instanceof HibernateProxy ? ((HibernateProxy) this).getHibernateLazyInitializer().getPersistentClass() : this.getClass();
        if (thisEffectiveClass != oEffectiveClass) return false;
        User user = (User) o;
        return false;
    }

    @Override
    public final int hashCode() {
        return this instanceof HibernateProxy ? ((HibernateProxy) this).getHibernateLazyInitializer().getPersistentClass().hashCode() : getClass().hashCode();
    }

    public UserDto map(UserDTOMapper userDTOMapper) throws InstantiationException, IllegalAccessException {
            return userDTOMapper.apply(this);
    }
}

