package com.luv2code.springsecurity.demo.controller;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;

import javax.annotation.PostConstruct;
import javax.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.propertyeditors.StringTrimmerEditor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.InitBinder;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import com.luv2code.springsecurity.demo.user.CrmUser;
import com.luv2code.springsecurity.demo.entity.Role;
import com.luv2code.springsecurity.demo.entity.User;
import com.luv2code.springsecurity.demo.service.UserService;

@Controller
@RequestMapping("/register")
public class RegistrationController {
	
    @Autowired
    private UserDetailsManager userDetailsManager;
    
    @Autowired 
    private UserService userService;
    
	private PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
	
    private Logger logger = Logger.getLogger(getClass().getName());
    
    private Map<String, String> roles;
    
	@InitBinder
	public void initBinder(WebDataBinder dataBinder) {
		
		StringTrimmerEditor stringTrimmerEditor = new StringTrimmerEditor(true);
		
		dataBinder.registerCustomEditor(String.class, stringTrimmerEditor);
	}	
	
	@GetMapping("/showRegistrationForm")
	public String showMyLoginPage(Model theModel) {
		
		theModel.addAttribute("crmUser", new CrmUser());
		
		//add roles to the model for form display
		theModel.addAttribute("roles", roles);
		
		return "registration-form";
	}

	@PostMapping("/processRegistrationForm")
	public String processRegistrationForm(
				@Valid @ModelAttribute("crmUser") CrmUser theCrmUser, 
				BindingResult theBindingResult, 
				Model theModel) {
		
		String userName = theCrmUser.getUserName();		
		logger.info("Processing registration form for: " + userName);
		
		// form validation
		 if (theBindingResult.hasErrors()){
			 
			 theModel.addAttribute("crmUser", new CrmUser());
			 
			 theModel.addAttribute("roles", roles);
			 
			 theModel.addAttribute("registrationError", "User name/password can not be empty.");

			 logger.warning("User name/password can not be empty.");
			 return "registration-form";
	        }

			// check the database if user already exists
			boolean userExists = doesUserExist(userName);
			
			if (userExists) {
	        	theModel.addAttribute("crmUser", new CrmUser());
				theModel.addAttribute("roles", roles);
	        	theModel.addAttribute("registrationError", "User name already exists.");
	
				logger.warning("User name already exists.");
	        	return "registration-form";
        }
        
     // encrypt the password
     //   String encodedPassword = passwordEncoder.encode(theCrmUser.getPassword());

        // prepend the encoding algorithm id
     //   encodedPassword = "{bcrypt}" + encodedPassword;
        
        //give user default role of employee
        List<Role> authorities = new ArrayList<Role>();
        
        authorities.add(new Role("ROLE_EMPLOYEE"));
        
        // if the user selected role other than employee, 
        // then add that one too (multiple roles)
        String formRole = theCrmUser.getFormRole();

        if (!formRole.equals("ROLE_EMPLOYEE")) {
        		authorities.add(new Role(formRole));
        }
        
        // create user object (from Spring Security framework)
        User tempUser = new User(userName, theCrmUser.getPassword(), theCrmUser.getFirstName(), theCrmUser.getLastName(), theCrmUser.getEmail(), authorities);

        // save user in the database
        userService.save(tempUser);
       
        
        logger.info("Successfully created user: " + userName);
        
        return "registration-confirmation";				
	}
	
	@PostConstruct
	protected void loadRoles() {
		//using hashmap, could also read this info from a database
		
		roles = new LinkedHashMap<String, String>();
		
		//key = the role, value= display to user
		
		roles.put("ROLE_EMPLOYEE", "Employee");
		roles.put("ROLE_MANAGER", "manager");
		roles.put("ROLE_ADMIN", "Admin");
	}
	
	private boolean doesUserExist(String userName) {
			
			logger.info("Checking if user exists: " + userName);
			
			// check the database if the user already exists
			boolean exists = userDetailsManager.userExists(userName);
			
			logger.info("User: " + userName + ", exists: " + exists);
			
			return exists;
	}
}
