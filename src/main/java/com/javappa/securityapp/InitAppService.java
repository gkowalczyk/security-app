package com.javappa.securityapp;

import com.javappa.securityapp.security.domain.Privilege;
import com.javappa.securityapp.security.domain.Role;
import com.javappa.securityapp.security.domain.RoleEnum;
import com.javappa.securityapp.security.domain.User;
import com.javappa.securityapp.security.repository.PrivilegeRepository;
import com.javappa.securityapp.security.repository.RoleRepository;
import com.javappa.securityapp.security.repository.UserRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@Service
@Transactional
public class InitAppService {

    private static final String DUMMY_ADMIN_USER = "jk";
    private static final String DUMMY_ADMIN_PASSWORD = "a123";
    private static final String DUMMY_ADMIN_FIRST_NAME = "Jan";
    private static final String DUMMY_ADMIN_LAST_NAME = "Kowalski";

    private static final String DUMMY_USER = "pn";
    private static final String DUMMY_PASSWORD = "pn098";
    private static final String DUMMY_FIRST_NAME = "Piotr";
    private static final String DUMMY_LAST_NAME = "Nowak";

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PrivilegeRepository privilegeRepository;

    private final PasswordEncoder passwordEncoder;

    public InitAppService(UserRepository userRepository, RoleRepository roleRepository,
                          PrivilegeRepository privilegeRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.privilegeRepository = privilegeRepository;
        this.passwordEncoder = passwordEncoder;
    }

    public void initData() {

        final Privilege readPrivilege = newPrivilege("ROLE_READ_PRIVILEGE");
        final Privilege writePrivilege = newPrivilege("ROLE_WRITE_PRIVILEGE");
        final Privilege apiReadPrivilege = newPrivilege("ROLE_API_READ_PRIVILEGE");
        final List<Privilege> adminPrivileges = new ArrayList<>(Arrays.asList(readPrivilege,
                                                                              writePrivilege,
                                                                              apiReadPrivilege));
        final List<Privilege> userPrivileges = new ArrayList<>(Arrays.asList(readPrivilege));

        final Role roleUser = newRole(RoleEnum.ROLE_USER.getValue(), userPrivileges);
        newUser(roleUser);
        final Role roleAdmin = newRole(RoleEnum.ROLE_ADMIN.getValue(), adminPrivileges);
        newAdminUser(roleAdmin);
    }

    private void newAdminUser(final Role roleAdmin) {

        User user = new User();
        user.setEmail(DUMMY_ADMIN_USER);
        user.setPassword(passwordEncoder.encode(DUMMY_ADMIN_PASSWORD));
        user.getRoles().add(roleAdmin);
        user.setFirstName(DUMMY_ADMIN_FIRST_NAME);
        user.setLastName(DUMMY_ADMIN_LAST_NAME);
        user.setEnabled(true);
        userRepository.save(user);
    }

    private void newUser(final Role roleUser) {

        User user = new User();
        user.setEmail(DUMMY_USER);
        user.setPassword(passwordEncoder.encode(DUMMY_PASSWORD));
        user.getRoles().add(roleUser);
        user.setFirstName(DUMMY_FIRST_NAME);
        user.setLastName(DUMMY_LAST_NAME);
        user.setEnabled(true);
        userRepository.save(user);
    }

    private Privilege newPrivilege(final String name) {

        Privilege privilege = privilegeRepository.findByName(name);
        if (privilege == null) {
            privilege = new Privilege(name);
            privilege = privilegeRepository.save(privilege);
        }

        return privilege;
    }

    private Role newRole(final String name, final List<Privilege> privileges) {

        Role role = roleRepository.findByName(name);
        if (role == null) {
            role = new Role(name);
        }
        role.setPrivileges(privileges);
        role = roleRepository.save(role);

        return role;
    }
}
