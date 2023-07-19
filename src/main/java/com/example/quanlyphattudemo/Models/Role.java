package com.example.quanlyphattudemo.Models;

import lombok.*;
import org.hibernate.annotations.NaturalId;

import javax.persistence.*;
import java.util.Set;

@Entity
@Table(name = "roles")
@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class Role {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "roleid")
    private int roleId;
    @Column(name = "rolename")
    @Enumerated( EnumType.STRING)
    @NaturalId
    private RoleName name;
//    @ManyToMany(mappedBy = "roles")
//    // LAZY để tránh việc truy xuất dữ liệu không cần thiết. Lúc nào cần thì mới query
//    @EqualsAndHashCode.Exclude
//    private Set<PhatTus> phatTuses;
}
