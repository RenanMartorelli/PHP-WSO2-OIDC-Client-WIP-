<?php 

// SCIM é uma API para fazer um CRUD de usuários de uma aplicação para outra
// no caso de um Service Provider (SP) para um Identity Provider (IdP).
// Os dados são trafegados em JSON e num modelo(schema) pré definido.

class ScimAPI {

    // Recebe o cpf para buscar o usuário, o IP do IdP e o access token Oauth.
    // caso o usuário exista retorna array associativo com os índices userId
    // e userType, caso contrário retorna um array vazio.

    public static function verificaUsuarioExiste($cpf,$accessToken,$ip){

        $header = array("Authorization: Bearer {$accessToken}",
                "Content-Type: application/json");
        $url = "https://{$ip}/scim2/Users?startIndex=1&count=1&domain=PRIMARY&filter=userName+eq+{$cpf}&attributes=userName,userType";
        echo "<br/>" . $url;
        $curl = curl_init();
        curl_setopt_array($curl, array(
            CURLOPT_URL => $url,
            CURLOPT_HTTPHEADER => $header,
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_RETURNTRANSFER => true,
        ));
        $response = curl_exec($curl);
        curl_close($curl);
        
        if ($response === false) {
            echo "Failed";
            echo curl_error($curl);
            echo "Failed";
            return;
        } elseif (json_decode($response)->error) {
            echo "Error:<br />";
            echo $response;
            die("erro ao pegar usuário");
        }

        if(!isset(json_decode($response,true)['Resources'][0]['id'])){
            return array();
        } else {
            $userId = json_decode($response,true)['Resources'][0]['id'];
            $userType = json_decode($response,true)['Resources'][0]['userType'];
            return array(
                "userId"=>$userId,
                "userType"=>$userType
            );
        }
    }

    // recebe o access token e os dados do usuário a ser criado,
    // retorna JSON no formato SCIM com os dados do usuário criado em caso de
    // sucesso e em caso de erro dados do erro.
    public static function criaUsuario($accessToken, $nome, $email, $sobrenome, $cpf, $ip){
        
        
    $url = "https://{$ip}/scim2/Users";
        
    $postData = array(
        'schemas' => array(),
        'name' => array(
            'familyName' => $sobrenome,
            'givenName' => $nome
        ),
        'userName' => $cpf,
        'password' => 'password',
	'emails' => array(
        	array(
            	'primary' => true,
            	'value' => $email
        	)
    	),
    	'EnterpriseUser' => array(
        '	askPassword' => true
		)
	);
    );

        $header = array("Authorization: Bearer {$accessToken}",
                "Content-Type: application/json");

        $curl = curl_init();
        curl_setopt_array($curl, array(
            CURLOPT_POST => TRUE,
            CURLOPT_URL => $url,
            CURLOPT_HTTPHEADER => $header,
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_POSTFIELDS => json_encode($postData)
        ));
        $response = curl_exec($curl);
        curl_close($curl);

        return json_decode($response, true);
                
    }

    // recebe o access token e os dados do usuário a ser atualizado,
    // retorna JSON no formato SCIM com os dados do usuário atualizado em caso de
    // sucesso. Em caso de erro, retorna dados do erro.

    public static function atualizaUsuario($accessToken, $userId, $nome, $sobrenome, $senha, $ip){

        $url = "https://{$ip}/scim2/Users/{$userId}";
        $postData = array(
            'schemas' => array('urn:ietf:params:scim:api:messages:2.0:PatchOp'),
            'Operations' => array(
                array(
                    'op' => 'add',
                    'value' => array(
                        'password' => $senha,
                        'name' => array(
                            'familyName' => $sobrenome,
                            'givenName' => $nome
                        ),
                )
            )
        )
    );

        $header = array("Authorization: Bearer {$accessToken}",
                "Content-Type: application/json");

        $curl = curl_init();
        curl_setopt_array($curl, array(
            CURLOPT_CUSTOMREQUEST => 'PATCH',
            CURLOPT_URL => $url,
            CURLOPT_HTTPHEADER => $header,
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_POSTFIELDS => json_encode($postData)
        ));
        $response = curl_exec($curl);
        curl_close($curl);

        echo "<br/><br/> Usuário atualizado! <br/><br/>";
        print_r(json_decode($response));
        return json_decode($response, true);
    }

    // recebe access token, ip, Id do usuário, nome do usuário Id do grupo, 
    // retorna JSON no formato SCIM com os dados do usuário atualizado em caso de
    // sucesso. Em caso de erro, retorna dados do erro.

    public static function adicionaUsuarioAoGrupo($access_token,$ip,$userId,$groupId,$username){
        $url = "https://{$ip}/scim2/Groups/{$groupId}";
            
        $postData = array(
        
          'schemas' => array('urn:ietf:params:scim:api:messages:2.0:PatchOp'),
          'Operations' => array(
            array(
             'op' => 'add',
             'value' =>
              array(
                'members' => array(
                    array(
                     'display' => $username,
                     'value' => $userId
                    )
                )
              )
            )
          )
        ); 
        
            $header = array("Authorization: Bearer {$access_token}",
                    "Content-Type: application/json");
        
            $curl = curl_init();
            curl_setopt_array($curl, array(
                CURLOPT_CUSTOMREQUEST => 'PATCH',
                CURLOPT_URL => $url,
                CURLOPT_HTTPHEADER => $header,
                CURLOPT_SSL_VERIFYPEER => false,
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_POSTFIELDS => json_encode($postData)
            ));
            $response = curl_exec($curl);
            curl_close($curl);
            
            print_r(json_decode($response));
            return json_decode($response, true);
        }

    //Recebe access token, ip do IdP e nome do Grupo (role) desejado.
    //retorna array com os dados, incluindo o $ip do grupo.
    public static function consultaGrupo($access_token,$ip,$groupName){
        global $userId, $userType;
        
        $header = array("Authorization: Bearer {$access_token}",
                "Content-Type: application/json");
        $url = "https://{$ip}/scim2/Groups";
    
        $curl = curl_init();
        curl_setopt_array($curl, array(
            CURLOPT_URL => $url,
            CURLOPT_HTTPHEADER => $header,
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_RETURNTRANSFER => true,
        ));
        $response = curl_exec($curl);
        curl_close($curl);

        // print_r(json_decode($response));
        return json_decode($response);
    }

    


}
